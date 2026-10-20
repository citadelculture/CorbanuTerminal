#!/usr/bin/env python3
"""Fixed hosted synthetic diagnostic; imported helpers never run their mains."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import sys
import tempfile
import time

BRANCH = 'refs/heads/codex/network-nested-containment-diagnostic-v1-20261020'
REPO = 'citadelculture/CorbanuTerminal'
PRESERVE = ('HOME', 'CODEX_HOME', 'CODEX_SANDBOX', 'CODEX_SANDBOX_NETWORK_DISABLED')
MEANINGFUL = {'SELF_HARDENING_REJECTED', 'NESTED_CONTAINMENT_REJECTED',
              'SYNTHETIC_NESTING_PATH_SUPPORTED_NOT_BROKER_QUALIFICATION'}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def environment(parent, root):
    env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'en_US.UTF-8',
           'TMPDIR': str(root / 'tmp'), 'PYTHONDONTWRITEBYTECODE': '1'}
    for key in PRESERVE:
        if key in parent: env[key] = parent[key]
    return env


def fixed_host(parent):
    return (sys.platform == 'darwin' and platform.release().split('.')[0] == '24'
            and platform.machine() == 'arm64' and os.geteuid() != 0
            and parent.get('GITHUB_ACTIONS') == 'true'
            and parent.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and parent.get('RUNNER_OS') == 'macOS'
            and parent.get('GITHUB_REPOSITORY') == REPO
            and parent.get('GITHUB_REF') == BRANCH
            and parent.get('GITHUB_EVENT_NAME') == 'push'
            and parent.get('GITHUB_RUN_ATTEMPT') == '1'
            and re.fullmatch(r'[0-9]+', parent.get('GITHUB_RUN_ID', '')) is not None)


def evidence_text(text, root, runtime):
    if re.search(r'(?i)\b(?:gh[pousr]_|github_pat_|sk-|xox[abprs]-)[A-Za-z0-9_-]{8,}'
                 r'|\bBearer\s+\S{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----', text):
        raise ValueError('sensitive_shape_hold')
    text = text.replace(str(root), '<OWNED>')
    if runtime.parent == Path('/var/tmp'):
        text = text.replace('/private' + str(runtime), '<SYNTHETIC_RUNTIME>')
    text = text.replace(str(runtime), '<SYNTHETIC_RUNTIME>')
    return re.sub(r'/Users/[^\s\"<>]+', '<HOSTED_USER_PATH>', text)


def remove_owned_runtime(runtime, identity):
    """Remove only this exact newly-created fixture and the two known socket dirs."""
    st = runtime.lstat()
    if (runtime.is_symlink() or (st.st_dev, st.st_ino, st.st_uid) != identity
            or st.st_uid != os.getuid() or not stat.S_ISDIR(st.st_mode)):
        raise RuntimeError('runtime_identity_changed')
    for item in runtime.iterdir():
        if item.name not in ('cbk-Pre001', 'cbk-Post01') or item.is_symlink() or not item.is_dir():
            raise RuntimeError('unexpected_fixture_entry')
        for entry in item.iterdir():
            if entry.name != 'c.sock' or not stat.S_ISSOCK(entry.lstat().st_mode):
                raise RuntimeError('unexpected_fixture_child')
            entry.unlink()
        item.rmdir()
    runtime.rmdir()
    return not runtime.exists()


def qualifies_capture(report):
    return (report.get('diagnostic', {}).get('status') in MEANINGFUL
            and report.get('allTrackedGroupsGone') is True
            and report.get('allCommandsComplete') is True
            and report.get('sentinelsUnchanged') is True
            and report.get('runtimeRemoved') is True
            and report.get('inheritedValuesPreserved') is True
            and report.get('error') is None)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--dispatch', action='store_true', required=True)
    p.add_argument('--pins-sha256', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    if not fixed_host(os.environ): raise RuntimeError('fixed_host_required')
    control = Path(__file__).resolve().parent
    pins_file = control / 'diagnostic-pins-v1.json'
    if sha(pins_file) != a.pins_sha256: raise RuntimeError('pins_mismatch')
    pins = json.loads(pins_file.read_text())
    for name, digest in pins['files'].items():
        if Path(name).name != name or sha(control / name) != digest:
            raise RuntimeError('control_mismatch')
    admission = json.loads((control / 'diagnostic-admission-v1.json').read_text())
    if (admission != {'diagnosticOnlyApproved': True, 'canaryApproved': False,
                      'buildApproved': False, 'pinsSha256': a.pins_sha256}):
        raise RuntimeError('exact_diagnostic_admission_required')
    build = load(control / 'bounded-command-original.py', 'bounded_command_original')
    measured = load(control / 'measurement-profile-original.py', 'measurement_profile_original')
    # This exact replay guards the inherited restrictions before any synthetic child.
    prior_root = Path('/private/tmp/network-build-39413144417-1')
    replay = measured.measurement_profile(build, prior_root, prior_root / 'measurement/foreign')
    if hashlib.sha256(replay.encode()).hexdigest() != pins['originalMeasurementProfileSha256']:
        raise RuntimeError('original_profile_replay_mismatch')
    root = Path('/private/tmp/network-diagnostic-' + os.environ['GITHUB_RUN_ID'] + '-1')
    root.mkdir(mode=0o700)
    for name in ('tmp', 'raw'): (root / name).mkdir(mode=0o700)
    output = a.output.resolve()
    output.mkdir(mode=0o700)
    rows, runtime, identity = [], None, None
    initial = {k: (k in os.environ, os.environ.get(k)) for k in PRESERVE}
    report = {'schema': 'network-nested-containment-diagnostic-v1', 'status': 'INCOMPLETE',
              'runId': os.environ['GITHUB_RUN_ID'], 'sourceCommit': pins['sourceCommit'],
              'pinsSha256': a.pins_sha256, 'commands': rows, 'diagnostic': {}, 'error': None,
              'canaryInvocations': 0, 'buildInvocations': 0, 'productBodiesExecuted': 0,
              'canaryReady': False, 'rewardClaim': False, 'runtimeRemoved': False,
              'rawPrivateStreamsUploaded': False, 'limits': {'wholeSeconds': 120, 'probeSeconds': 20,
                'perStreamBytes': build.CAPTURE_LIMIT, 'publicDiagnosticBytes': 65536}}
    foreign = root / 'foreign'
    sentinel = root / 'inner-only-sentinel'
    foreign.write_bytes(b'SYNTHETIC_FOREIGN_SENTINEL\n')
    sentinel.write_bytes(b'SYNTHETIC_INNER_ONLY_SENTINEL\n')
    sentinels = {f.name: sha(f) for f in (foreign, sentinel)}
    deadline = time.monotonic() + 120
    try:
        report['freeBytesBefore'] = shutil.disk_usage(root).free
        if report['freeBytesBefore'] < 6 * 1024**3: raise build.Hold('six_gib_diagnostic_admission')
        python = Path(sys.executable).resolve(strict=True)
        if not str(python).startswith(('/Applications/', '/Library/Frameworks/', '/opt/')):
            raise build.Hold('direct_public_python_path_required')
        report['pythonSha256'] = sha(python)
        report['pythonVersion'] = list(sys.version_info[:3])
        child = root / 'synthetic-probe.py'
        shutil.copyfile(control / 'synthetic-nested-seatbelt-probe-v1.py', child)
        if sha(child) != pins['files']['synthetic-nested-seatbelt-probe-v1.py']:
            raise build.Hold('copied_child_mismatch')
        env = environment(os.environ, root)
        report['inheritedValuesPreserved'] = all((k in env, env.get(k)) == initial[k] for k in PRESERVE)
        profile = root / 'measurement.sb'
        profile.write_text(measured.measurement_profile(build, root, foreign))
        report['outerProfileSha256'] = sha(profile)
        (output / 'measurement.sb').write_text(evidence_text(profile.read_text(), root, Path('/unused-runtime')))
        build.command('outer-profile-parse', ['/usr/bin/true'], root, env, root / 'raw', rows,
                      deadline, 10, root, profile)
        runtime = Path(tempfile.mkdtemp(prefix='corbanu-credential-canary-', dir='/var/tmp'))
        st = runtime.lstat(); identity = (st.st_dev, st.st_ino, st.st_uid)
        report['runtimeMode'] = stat.S_IMODE(st.st_mode)
        argv = [str(python), '-I', '-B', str(child), '--dispatch', '--runtime', str(runtime),
                '--sentinel', str(sentinel), '--foreign', str(foreign)]
        try:
            build.command('nested-broker-profile', argv, root, env, root / 'raw', rows,
                          deadline, 20, root, profile)
        finally:
            result = root / 'raw/nested-broker-profile.stdout'
            if result.exists() and result.stat().st_size <= 65536:
                try: report['diagnostic'] = json.loads(result.read_text())
                except (ValueError, UnicodeError): pass
    except BaseException as e:
        report['error'] = str(e) if isinstance(e, build.Hold) else type(e).__name__
    finally:
        report['allTrackedGroupsGone'] = bool(rows) and all(r['groupGone'] for r in rows)
        report['allCommandsComplete'] = len(rows) == 2 and all(build.command_ok(r) for r in rows)
        report['sentinelsUnchanged'] = all(sha(f) == sentinels[f.name] for f in (foreign, sentinel))
        report['inheritedValuesPreserved'] = report.get('inheritedValuesPreserved', False) and all(
            (k in os.environ, os.environ.get(k)) == initial[k] for k in PRESERVE)
        if runtime is not None and report['allTrackedGroupsGone']:
            try: report['runtimeRemoved'] = remove_owned_runtime(runtime, identity)
            except BaseException as e: report['cleanupError'] = type(e).__name__
        report['streamExports'] = []
        for row in rows:
            for stream in ('stdout', 'stderr'):
                path = root / 'raw' / (row['label'] + '.' + stream)
                entry = {'name': path.name, 'rawSha256': sha(path), 'rawBytes': path.stat().st_size}
                try:
                    text = evidence_text(path.read_text(), root, runtime or Path('/unused-runtime'))
                    dst = output / path.name
                    dst.write_text(text)
                    entry.update(exportSha256=sha(dst), exportBytes=dst.stat().st_size, complete=True)
                except (ValueError, UnicodeError):
                    entry['withheld'] = True; report['error'] = 'stream_export_held'
                report['streamExports'].append(entry)
        if qualifies_capture(report):
            report['status'] = 'DIAGNOSTIC_CAPTURED_NOT_CANARY_QUALIFICATION'
        text = evidence_text(json.dumps(report, indent=2, sort_keys=True) + '\n', root,
                             runtime or Path('/unused-runtime'))
        (output / 'diagnostic-result.json').write_text(text)
    return 0 if report['status'] == 'DIAGNOSTIC_CAPTURED_NOT_CANARY_QUALIFICATION' else 1


if __name__ == '__main__':
    sys.exit(main())
