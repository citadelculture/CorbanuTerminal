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
EXPECTED_CANDIDATE = 'cf5ab5befa32e9e555c62c2e2b400839d32fa47d'
AFFECTED = 'test(security::revocation_view::tests::) | test(bottom_pane::security_level_picker::issue_1047_tests::)'


def record_final_junit(path, expected_names, evidence, label):
    # Same exact16 contract, factored for inert tests of the preserved report.
    testcases = list(ET.parse(path).getroot().iter('testcase'))
    expected = 16
    if len(testcases) != expected or any(case.find('skipped') is not None for case in testcases):
        raise RuntimeError(f'Execution record count/skip mismatch: {label}, {len(testcases)} vs {expected}')
    if sorted(case.attrib.get('name', '') for case in testcases) != sorted(expected_names):
        raise RuntimeError('Exact selected test names do not match the frozen inventory')
    write_json(evidence / (label + '-test-records.json'), {
        'expected': expected, 'actual': len(testcases),
        'names': [case.attrib.get('name') for case in testcases],
        'failures': sum(case.find('failure') is not None for case in testcases),
        'bodySkipInspectionStillRequired': True})
    if any(case.find('failure') is not None or case.find('error') is not None for case in testcases):
        raise RuntimeError('Final selected test records contain a failure or error')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--lane', choices=['final'], required=True)
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
    binding_path = method / 'final-binding.json'
    if not binding_path.is_file():
        raise RuntimeError('Final lane is inert: actual acceptance/full-fmt source binding is absent')
    source_pins = json.loads(binding_path.read_text())
    if source_pins['state'] != 'ROOT_ACCEPTED_FULLFMT_FINAL_SOURCE_BOUND' or source_pins['capturedCandidate'] != EXPECTED_CANDIDATE:
        raise RuntimeError('Final source acceptance/full-fmt binding is invalid')
    for field in ('verifiedCaptureReceiptSha256', 'snapshotAcceptanceReceiptSha256', 'fullFmtReceiptSha256', 'fullTrackedManifestSha256'):
        if not re.fullmatch(r'[a-f0-9]{64}', source_pins.get(field, '')):
            raise RuntimeError('Actual root acceptance/full-fmt manifest evidence binding is missing')
    pin, tree = source_pins['commit'], source_pins['tree']
    expected_source_hashes = source_pins['sourceHashes']
    if len(source_pins['expectedTests']) != 16 or len(source_pins['acceptedSnapshots']) != 3:
        raise RuntimeError('Final binding does not cover exactly16tests/3accepted snapshots')
    uid, gid = os.getuid(), os.getgid()
    if uid == 0:
        raise RuntimeError('Host job UID must be non-root')
    prefix = 'issue1094-' + os.environ['GITHUB_RUN_ID'] + '-' + os.environ.get('GITHUB_RUN_ATTEMPT', '1') + '-' + args.lane
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
        'base': '2469e554dd1760917eb3594621abc152ce29c184',
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
                     '--env', 'INSTA_UPDATE=no',
                     '--env', 'INSTA_FORCE_PASS=0',
                     '--env', 'SOURCE_COMMIT=' + pin,
                     '--env', 'EXPECTED_TOOL_MANIFEST_SHA256=' + tool_manifest_sha256]
            for ns in ('mnt', 'pid', 'ipc', 'net'):
                argv += ['--env', 'HOST_NS_' + ns.upper() + '=' + os.readlink('/proc/self/ns/' + ns)]
            argv += [prepared_image_digest]
        return argv

    def native(label, expression, timeout, allow_failure=False):
        nonlocal cache_evidence_preserved
        name = prefix + '-' + label
        report_root = work / 'reports' / label
        report_root.mkdir(parents=True, exist_ok=False)
        # Only an empty mountpoint appears in the host source checkout. The
        # report bytes stay in owned work/reports, outside the source mount.
        report_mountpoint = source / REPORT_MOUNT.relative_to('/src')
        report_mountpoint.mkdir(parents=True, exist_ok=False)
        argv = create(name, report_root=report_root)
        argv += ['python3', '/method/container_entry.py', label, expression]
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
            rc = run(label, ['docker', 'start', '--attach', name], timeout, name, allow_failure)
        finally:
            try:
                try:
                    owned_stop(name)
                finally:
                    # Preserve exact accidental pending snapshots if present,
                    # while the strict final source invariant still forbids them.
                    try:
                        pending_paths = {row['path'] + '.new' for row in source_pins['acceptedSnapshots']}
                        capture_report_evidence(report_root, source, evidence, label,
                                                pending_paths, available, 8 * GIB)
                    finally:
                        preserve_attempt(scratch / 'target', evidence, label, available, 8 * GIB)
                cache_evidence_preserved = True
            finally:
                source_state(source, (pin, tree), expected_source_hashes, set(), evidence, label + '-after')
        # Same exact16 checks, using the preserved profile.local report.
        record_final_junit(evidence / (label + '-junit-0.xml'), source_pins['expectedTests'], evidence, label)
        binary_record = json.loads((evidence / (label + '-executed-binary.json')).read_text())
        if not binary_record.get('metadataAndPreservedBinaryMatch'):
            raise RuntimeError('Actual executed binary metadata/retention was not proven')
        retained = evidence / binary_record['retainedPath']
        if digest(retained) != binary_record['sha256'] or retained.stat().st_size != binary_record['bytes']:
            raise RuntimeError('Retained binary identity drift')
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
        native('affected', AFFECTED, 5400)
        write_json(evidence / 'final-native-evidence-hold.json', {
            'state': 'EXACT16_RECORDS_REQUIRE_RAW_BODY_SKIP_AND_SEMANTIC_INSPECTION',
            'expectedCount': 16, 'junitSkipped': 0, 'sourceCommit': pin,
            'bodySkipAbsenceNotAutomaticallyClaimed': True,
            'snapshotMutation': False, 'snapshotForcePass': False,
            'trueTuiAndCodeBlindGatesRemainSeparate': True})
        outcome = 'FINAL16_RAW_RESULTS_RETAINED_PENDING_EVIDENCE_INSPECTION'
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
                'snapshotAcceptanceBound': True, 'snapshotsAcceptedByThisRun': False,
                'readyForHumanTesting': False})
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
