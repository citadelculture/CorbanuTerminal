#!/usr/bin/env python3
"""Bounded disposable Docker driver. Preparation only until root approves execution."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from hosted_controls import now, digest, write_json, run_bounded, source_state, cleanup_resources, preserve_attempt
from report_evidence import REPORT_MOUNT, capture_report_evidence

GIB = 1024 ** 3
IMAGE = 'rust:1.99.1-bookworm@sha256:8bf7188ae46ad73b801c8d405eedc13ce63a7852b562885743a56890723549a8'
PINS = {
    'compile': ('7a280f934d316a0bc6ce4b58502cb2d46ac4df6d', 'da0ec342e7df00435917f53759f7ce5e9d045b15'),
    'capture': ('7a280f934d316a0bc6ce4b58502cb2d46ac4df6d', 'da0ec342e7df00435917f53759f7ce5e9d045b15'),
}
CAPTURE_TESTS = (
    'chatwidget::named_account_login::tests::issue1290_named_account_login_snapshots',
    'chatwidget::named_account_login::tests::issue1290_finishing_sign_in_snapshot',
)
CAPTURE_EXPRESSION = ' or '.join('test(=' + name + ')' for name in CAPTURE_TESTS)


def allocate_reports(work, source, label):
    # Per-invocation report bytes never share a namespace. An empty mountpoint
    # may survive a previous invocation; it is not itself an untracked file.
    report_root = work / 'reports' / label
    report_root.mkdir(parents=True, exist_ok=False)
    mountpoint = source / REPORT_MOUNT.relative_to('/src')
    if mountpoint.is_symlink():
        raise RuntimeError('Report mountpoint is a symlink')
    mountpoint.mkdir(parents=True, exist_ok=True)
    if not mountpoint.is_dir() or any(mountpoint.iterdir()):
        raise RuntimeError('Report mountpoint contains source-side report bytes')
    return report_root


def detect_body_skip_lines(log, expected_names):
    # --status-level all prints SKIP rows for excluded tests. They are not body
    # skips; reject a selected SKIP row and explicit skip messages instead.
    rejected = []
    for line in log.splitlines():
        if re.match(r'^\s*SKIP\s*\[', line):
            if any(re.search(r'(?<![\w:])' + re.escape(name) + r'(?![\w:])', line)
                   for name in expected_names):
                rejected.append(line)
            continue
        if re.search(r'(?i)\bskipping\b|\bskip(?:ped)?\s+(?:because|due|this|test)', line):
            rejected.append(line)
    return rejected


def validate_test_records(evidence, label, expected_names):
    # All evidence has already been copied before these gates run.
    path = evidence / (label + '-junit-0.xml')
    cases = list(ET.parse(path).getroot().iter('testcase')) if path.exists() else []
    if expected_names and not path.exists():
        raise RuntimeError('Required snapshot capture JUnit report is missing')
    if sorted(case.attrib.get('name', '') for case in cases) != sorted(expected_names):
        raise RuntimeError('Exact selected test names/count do not match frozen inventory')
    if any(case.find(tag) is not None for case in cases for tag in ('skipped', 'failure', 'error')):
        raise RuntimeError('Selected execution record contains skip/failure/error')
    log = (evidence / (label + '.log')).read_text(errors='replace')
    skip_lines = detect_body_skip_lines(log, expected_names)
    if skip_lines:
        write_json(evidence / (label + '-body-skip-rejection.json'), {'lines': skip_lines})
        raise RuntimeError('Possible body skip in native output; fail closed')
    write_json(evidence / (label + '-test-records.json'), {
        'expected': len(expected_names), 'actual': len(cases),
        'names': [case.attrib.get('name') for case in cases],
        'failures': 0, 'bodySkipScan': 'no matching skip line',
        'qualification': False, 'compileOnly': not expected_names})
    binary_record = json.loads((evidence / (label + '-executed-binary.json')).read_text())
    if not binary_record.get('metadataAndPreservedBinaryMatch'):
        raise RuntimeError('Exact attributed binary metadata/retention was not proven')
    retained = evidence / binary_record['retainedPath']
    if digest(retained) != binary_record['sha256'] or retained.stat().st_size != binary_record['bytes']:
        raise RuntimeError('Retained binary identity drift')
    if sorted(binary_record['selectedTests']) != sorted(expected_names):
        raise RuntimeError('Metadata selected names drift')
    return binary_record


def dispatch_stage(lane, native, evidence, pending_snapshots):
    if lane == 'compile':
        native('compile', 'bin', 'none()', 5400, [])
        write_json(evidence / 'compile-only-result.json', {
            'state': 'COMPILE_ONLY_NO_BEHAVIOR_CLAIM', 'testsExecuted': 0,
            'nextStage': 'Separate fresh source-bound capture job, gated on this job success'})
        return 'PRODUCTION_COMPILE_ONLY_COMPLETED'
    if lane != 'capture':
        raise RuntimeError('Final-test dispatch is not admitted by this stage1 controller')
    native('generate', 'lib', CAPTURE_EXPRESSION, 5400, list(CAPTURE_TESTS))
    snapshots = sorted(evidence / Path(name).name for name in pending_snapshots
                       if (evidence / Path(name).name).is_file())
    if len(snapshots) != 4:
        raise RuntimeError('Expected exactly four actually generated pending snapshots')
    write_json(evidence / 'generated-snapshots.json', {p.name: digest(p) for p in snapshots})
    write_json(evidence / 'final-tests-hold.json', {
        'state': 'BLOCKED_PENDING_SNAPSHOT_INSPECTION_ACCEPTANCE_FULLFMT_AND_FINAL_COMMIT',
        'expectedTuiTestCount': 13, 'expectedLoginTestCount': 1,
        'captureIsNotFinalValidation': True, 'finalDispatchEnabled': False})
    return 'TWO_CAPTURE_RESULTS_AND_FOUR_PENDING_SNAPSHOTS_REQUIRE_INSPECTION'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--lane', choices=PINS, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    method = Path(__file__).resolve().parent
    work = args.work.resolve()
    evidence = args.evidence.resolve()
    work.mkdir(parents=True, exist_ok=False)
    evidence.mkdir(parents=True, exist_ok=False)
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
        raise RuntimeError('This method admits only a fresh GitHub-hosted disposable runner')
    if os.environ.get('GITHUB_REPOSITORY') != 'citadelculture/CorbanuTerminal':
        raise RuntimeError('Wrong publication destination')
    pin, tree = PINS[args.lane]
    source_pins = json.loads((method / 'source-pins-v1.json').read_text())
    expected_source_hashes = source_pins['lanes'][args.lane]
    pending_snapshots = set(source_pins['pendingSnapshots'])
    if source_pins['sourceCommit'] != pin or source_pins['sourceTree'] != tree:
        raise RuntimeError('Source binding differs from frozen controller')
    if source_pins['captureTests'] != list(CAPTURE_TESTS) or source_pins['finalDispatchEnabled']:
        raise RuntimeError('Stage1 selector/final-dispatch binding drift')
    uid, gid = os.getuid(), os.getgid()
    if uid == 0:
        raise RuntimeError('Host job UID must be non-root')
    prefix = 'issue1290-' + os.environ['GITHUB_RUN_ID'] + '-' + os.environ.get('GITHUB_RUN_ATTEMPT', '1') + '-' + args.lane
    prefix = re.sub('[^a-zA-Z0-9_.-]', '-', prefix)
    image = prefix + ':prepared'
    prepared_image_digest = None
    tool_manifest_sha256 = None
    cache_evidence_preserved = True
    containers = []
    results = []
    cleanup = []
    cache = work / 'cache'
    scratch = work / 'scratch'
    cache.mkdir()
    scratch.mkdir()
    (cache / 'cargo').mkdir()
    # Let pinned Cargo create scratch/target itself, including its ownership tag.
    launch = {
        'startedAt': now(), 'lane': args.lane, 'sourceCommit': pin, 'sourceTree': tree,
        'image': IMAGE, 'workflowSha': os.environ.get('GITHUB_SHA'),
        'base': '353c54916b7f7b542507d08695b984cc05921cc0',
        'hostedImageOS': os.environ.get('ImageOS'), 'hostedImageVersion': os.environ.get('ImageVersion'),
        'controlMarkers': {k: os.environ[k] for k in ('CODEX_SANDBOX', 'CODEX_SANDBOX_NETWORK_DISABLED') if k in os.environ},
        'methodHashes': {p.name: digest(p) for p in method.iterdir() if p.is_file()},
        'admissionGiB': 40, 'nativeAdmissionGiB': 32, 'continuousReserveGiB': 8,
        'memoryLimitGiB': 12, 'buildJobs': 2, 'testThreads': 1,
        'claims': 'Ordinary fixture unit/snapshot evidence only; no TUI/code-blind/human-ready qualification',
    }
    write_json(evidence / 'launch.json', launch)

    def available():
        return min(shutil.disk_usage(work).free, shutil.disk_usage('/var/lib/docker').free)

    def admit(gib):
        free = available()
        if free < gib * GIB:
            raise RuntimeError(f'Prelaunch disk admission refused: {free} bytes < {gib} GiB')

    def short(argv):
        return subprocess.run(argv, capture_output=True, text=True, timeout=30)

    def owned_stop(name):
        # The exact owned container encompasses every product descendant.
        record = {'container': name, 'startedAt': now()}
        record['absent'] = False
        for action, command in [('stop', ['docker', 'stop', '--time', '10', name]),
                                ('remove', ['docker', 'rm', '--force', name]),
                                ('verify', ['docker', 'container', 'inspect', name])]:
            try:
                result = short(command)
                record[action] = {'exitCode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}
                if action == 'verify':
                    record['absent'] = result.returncode != 0 and 'No such' in result.stderr
            except BaseException as error:
                record[action] = {'error': type(error).__name__ + ': ' + str(error)}
        cleanup.append(record)
        if not record['absent']:
            raise RuntimeError('Owned container absence was not proven: ' + name)

    def run(label, argv, seconds, container=None, allow_failure=False):
        return run_bounded(label, argv, seconds, evidence, results, available, 8 * GIB,
                           (lambda: owned_stop(container)) if container else None,
                           allow_failure)

    def create(name, online=False, report_root=None):
        containers.append(name)
        argv = ['docker', 'create', '--name', name, '--network', 'bridge' if online else 'none',
                '--memory', '12g', '--memory-swap', '12g', '--cpus', '2', '--pids-limit', '512',
                '--mount', f'type=bind,src={source},dst=/src' + (',readonly' if online else ''),
                '--mount', f'type=bind,src={method},dst=/method,readonly',
                '--mount', f'type=bind,src={cache},dst=/cache',
                '--mount', f'type=bind,src={scratch},dst=/scratch',
                '--mount', f'type=bind,src={evidence},dst=/out',
                '--workdir', '/src/codex-rs', '--env', 'CARGO_HOME=/cache/cargo',
                '--env', 'CARGO_INCREMENTAL=0', '--env', 'CARGO_BUILD_JOBS=2',
                '--env', 'CARGO_PROFILE_DEV_DEBUG=0', '--env', 'CARGO_PROFILE_TEST_DEBUG=0',
                '--env', 'CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=true', '--env', 'CARGO_PROFILE_TEST_DEBUG_ASSERTIONS=true',
                '--env', 'CARGO_TARGET_DIR=/scratch/target', '--env', 'CARGO_NET_GIT_FETCH_WITH_CLI=true']
        for key in ('CODEX_SANDBOX', 'CODEX_SANDBOX_NETWORK_DISABLED'):
            if key in os.environ:
                argv += ['--env', key + '=' + os.environ[key]]
        if online:
            argv += ['--env', 'FIXTURE_UID=' + str(uid), '--env', 'FIXTURE_GID=' + str(gid), IMAGE]
        else:
            if report_root is None:
                raise RuntimeError('Native attempt requires a separate exact report-store mount')
            argv += ['--mount', f'type=bind,src={report_root},dst={REPORT_MOUNT}']
            argv += ['--read-only', '--cap-drop=ALL', '--security-opt', 'no-new-privileges=true',
                     '--user', f'{uid}:{gid}', '--tmpfs', '/tmp:rw,nosuid,nodev,size=2147483648',
                     '--env', 'CARGO_NET_OFFLINE=true', '--env', 'CARGO_TERM_COLOR=never',
                     '--env', 'PYTHONDONTWRITEBYTECODE=1',
                     '--env', 'INSTA_UPDATE=new' if name.endswith('-generate') else 'INSTA_UPDATE=no',
                     '--env', 'INSTA_FORCE_PASS=1' if name.endswith('-generate') else 'INSTA_FORCE_PASS=0',
                     '--env', 'SOURCE_COMMIT=' + pin,
                     '--env', 'EXPECTED_TOOL_MANIFEST_SHA256=' + tool_manifest_sha256]
            for ns in ('mnt', 'pid', 'ipc', 'net'):
                argv += ['--env', 'HOST_NS_' + ns.upper() + '=' + os.readlink('/proc/self/ns/' + ns)]
            argv += [prepared_image_digest]
        return argv

    def native(label, kind, expression, timeout, expected_names):
        nonlocal cache_evidence_preserved
        name = prefix + '-' + label
        report_root = allocate_reports(work, source, label)
        argv = create(name, report_root=report_root)
        argv += ['python3', '/method/container_entry.py', label, kind, expression, *expected_names]
        run(label + '-create', argv, 60)
        inspect = short(['docker', 'inspect', name])
        if inspect.returncode:
            raise RuntimeError('Cannot inspect exact native container')
        obj = json.loads(inspect.stdout)[0]
        if obj['Image'] != prepared_image_digest:
            raise RuntimeError('Native container is not the frozen prepared image')
        host_config = obj['HostConfig']
        if host_config['Privileged'] or host_config['NetworkMode'] != 'none' or not host_config['ReadonlyRootfs']:
            raise RuntimeError('Container host security configuration drift')
        if host_config['PidMode'] or host_config['IpcMode'] not in ('private', ''):
            raise RuntimeError('Host/shared process or IPC namespace configured')
        if host_config['CapAdd'] or host_config['CapDrop'] != ['ALL']:
            raise RuntimeError('Unexpected native container capabilities')
        report_mounts = [m for m in obj['Mounts'] if m['Destination'] == str(REPORT_MOUNT)]
        if (len(report_mounts) != 1 or report_mounts[0]['Type'] != 'bind'
                or report_mounts[0]['Source'] != str(report_root) or not report_mounts[0]['RW']):
            raise RuntimeError('Exact separate native report-store mount not proven')
        # Persist only this known synthetic configuration, never ambient host env.
        write_json(evidence / (label + '-container-config.json'), {
            'id': obj['Id'], 'image': obj['Image'], 'hostConfig': host_config,
            'mounts': obj['Mounts'], 'uid': obj['Config']['User']})
        source_state(source, (pin, tree), expected_source_hashes, set(), evidence, label + '-before')
        cache_evidence_preserved = False
        try:
            rc = run(label, ['docker', 'start', '--attach', name], timeout, name)
        finally:
            try:
                try:
                    owned_stop(name)
                finally:
                    # Capture each actual report/snapshot before strict source
                    # rejection can interrupt the path. Preserve binary evidence
                    # even if report capture itself reports an error.
                    try:
                        capture_report_evidence(report_root, source, evidence, label,
                                                pending_snapshots if label == 'generate' else set(),
                                                available, 8 * GIB)
                    finally:
                        preserve_attempt(scratch / 'target', evidence, label, available, 8 * GIB)
                cache_evidence_preserved = True
            finally:
                source_state(source, (pin, tree), expected_source_hashes, pending_snapshots if label == 'generate' else set(), evidence, label + '-after')
        validate_test_records(evidence, label, expected_names)
        return rc

    outcome = 'FAILED_OR_UNQUALIFIED'
    try:
        source_state(source, (pin, tree), expected_source_hashes, set(), evidence, 'initial')
        admit(40)
        memory = int(re.search(r'^MemAvailable:\s+(\d+)', Path('/proc/meminfo').read_text(), re.M)[1]) * 1024
        if memory < 13 * GIB:
            raise RuntimeError('At least 13 GiB available RAM required for a 12 GiB container limit')
        run('docker-capability', ['docker', 'version'], 30)
        run('public-base-image-pull', ['docker', 'pull', IMAGE], 600)
        prep = prefix + '-prepare'
        run('prepare-create', create(prep, online=True) + ['bash', '/method/prepare-public-tools.sh'], 60)
        run('public-prerequisites', ['docker', 'start', '--attach', prep], 1800, prep)
        run('freeze-tool-manifest-copy', ['docker', 'cp', prep + ':/opt/issue1094-tool-manifest.json', str(evidence / 'frozen-tool-manifest.json')], 60)
        tool_manifest_sha256 = digest(evidence / 'frozen-tool-manifest.json')
        run('freeze-prepared-image', ['docker', 'commit', prep, image], 300)
        observed_image = short(['docker', 'image', 'inspect', '--format', '{{.Id}}', image])
        if observed_image.returncode or not re.fullmatch(r'sha256:[a-f0-9]{64}', observed_image.stdout.strip()):
            raise RuntimeError('Frozen prepared image identity unavailable')
        prepared_image_digest = observed_image.stdout.strip()
        write_json(evidence / 'prepared-image-binding.json', {'image': prepared_image_digest, 'toolManifestSha256': tool_manifest_sha256})
        owned_stop(prep)
        admit(32)
        outcome = dispatch_stage(args.lane, native, evidence, pending_snapshots)
    except BaseException as exc:
        write_json(evidence / 'failure.json', {'at': now(), 'type': type(exc).__name__, 'message': str(exc)})
        raise
    finally:
        def remove_image():
            record = {'image': image, 'absent': False}
            for action, command in [('remove', ['docker', 'image', 'rm', '--force', image]),
                                    ('verify', ['docker', 'image', 'inspect', prepared_image_digest or image])]:
                try:
                    result = short(command)
                    record[action] = {'exitCode': result.returncode, 'stderr': result.stderr}
                    if action == 'verify':
                        record['absent'] = result.returncode != 0 and 'No such' in result.stderr
                except BaseException as error:
                    record[action] = {'error': type(error).__name__ + ': ' + str(error)}
            write_json(evidence / 'image-cleanup.json', record)
            return record['absent']

        def remove_cache():
            if not cache_evidence_preserved:
                raise RuntimeError('Native artifact preservation incomplete; retain owned cache')
            subprocess.run(['rm', '-rf', '--', str(work)], check=True, timeout=120)
            return not work.exists()

        cleanup_result = {'passed': False, 'errors': ['cleanup not reached']}
        try:
            cleanup_result = cleanup_resources(containers, results, owned_stop, remove_image, remove_cache)
        except BaseException as error:
            cleanup_result = {'passed': False, 'errors': [type(error).__name__ + ': ' + str(error)]}
        finally:
            write_json(evidence / 'terminal.json', {
                'at': now(), 'outcome': outcome, 'stages': results, 'containerCleanup': cleanup,
                'cleanup': cleanup_result, 'behaviorQualified': False, 'tuiQualified': False,
                'snapshotsAccepted': False, 'readyForHumanTesting': False})
        if not cleanup_result['passed']:
            raise RuntimeError('Cleanup incomplete or unknown; see preserved terminal receipt')


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        # Includes bootstrap failures before any native child can exist.
        if '--evidence' in sys.argv:
            destination = Path(sys.argv[sys.argv.index('--evidence') + 1])
            if destination.is_dir() and not (destination / 'terminal.json').exists():
                write_json(destination / 'terminal.json', {
                    'at': now(), 'outcome': 'BOOTSTRAP_OR_UNEXPECTED_FAILURE',
                    'error': type(error).__name__ + ': ' + str(error),
                    'cleanup': {'passed': False, 'state': 'not_proven'},
                    'behaviorQualified': False, 'readyForHumanTesting': False})
        raise
