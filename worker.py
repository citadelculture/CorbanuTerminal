#!/usr/bin/env python3
"""One ordinary integration campaign in a credential-free hosted compartment."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import selectors
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import xml.etree.ElementTree as ET

ROOT = Path('/owned')
SOURCE = ROOT / 'source'
CONTROL = Path('/control')
GIB = 1024 ** 3
MAX_STREAM = 32 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MARKERS = ('CODEX_SANDBOX', 'CODEX_SANDBOX_NETWORK_DISABLED', 'CODEX_SANDBOX_USER_NAMESPACES_DENIED')
CASES = {
 'suite::subagent_notifications::subagent_notification_is_included_without_wait': 'ISSUE1177_EXECUTED:original_without_wait',
 'suite::subagent_notifications::direct_operator_turn_in_spawned_child_does_not_notify_parent': 'ISSUE1177_EXECUTED:direct_operator_no_notification',
 'suite::subagent_notifications::readiness_tests::persisted_row_waits_for_delivery_then_reaches_turn_two': 'ISSUE1177_EXECUTED:controlled_delivery_gap',
 'suite::subagent_notifications::readiness_tests::undelivered_row_times_out_and_turn_two_oracle_rejects': 'ISSUE1177_EXECUTED:undelivered_timeout_and_oracle_rejection',
}
ANSI = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')

class Hold(RuntimeError):
    pass

def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for b in iter(lambda: f.read(1048576), b""):
            h.update(b)
    return h.hexdigest()


def save(path, value):
    with Path(path).open("x") as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write("\n")


def proc_table():
    table = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            # comm may contain spaces and parentheses: split after its final ')'.
            tail = (entry / "stat").read_text().rsplit(")", 1)[1].split()
            table[int(entry.name)] = (int(tail[1]), int(tail[19]))
        except (OSError, ValueError, IndexError):
            pass
    return table


def children():
    table, owned = proc_table(), set()
    changed = True
    while changed:
        changed = False
        for pid, (ppid, birth) in table.items():
            if pid not in owned and (ppid == os.getpid() or ppid in owned):
                owned.add(pid)
                changed = True
    return {pid: table[pid][1] for pid in owned}



def descendant_states(owned):
    """Only process identity/state, never argv, environment or command names."""
    rows = []
    for pid, birth in sorted(owned.items()):
        try:
            tail = (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()
            if int(tail[19]) == birth:
                rows.append({"pid": pid, "parentPid": int(tail[1]),
                             "birthTick": birth, "state": tail[0]})
        except (OSError, ValueError, IndexError):
            pass
    return rows


def reap_exited_descendants():
    """Called only after the Popen leader is reaped. Live children still hold."""
    before = descendant_states(children())
    reaped = []
    for _ in range(8):
        progress = False
        for row in descendant_states(children()):
            # waitpid is restricted to actual adopted, already exited children.
            # Recheck the birth identity so a reused numeric PID is never reaped.
            if row["parentPid"] != os.getpid() or row["state"] not in ("Z", "X"):
                continue
            if proc_table().get(row["pid"], (None, None)) != (os.getpid(), row["birthTick"]):
                continue
            try:
                pid, _status = os.waitpid(row["pid"], os.WNOHANG)
            except (ChildProcessError, ProcessLookupError):
                continue
            if pid == row["pid"]:
                reaped.append(row)
                progress = True
        if not progress:
            break
    remaining = children()
    return {"before": before, "reapedExited": reaped,
            "remaining": descendant_states(remaining), "remainingCount": len(remaining)}


def orphan_reaping_fixture_argv():
    # Synthetic process-only preflight; no repository/product code or networking.
    return ["/usr/bin/python3", "-I", "-B", "-c",
            "import os,time; child=os.fork(); "
            "time.sleep(0.05) if child == 0 else None; os._exit(0)"]


def cleanup(process):
    # Linux subreaper adopts orphaned command/test children, including new groups.
    process.poll()
    initial = children()
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for pid, birth in children().items():
            if proc_table().get(pid, (None, None))[1] == birth:
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    pass
        end = time.monotonic() + 3
        while time.monotonic() < end:
            process.poll()
            for pid in list(children()):
                if pid != process.pid:
                    try:
                        os.waitpid(pid, os.WNOHANG)
                    except (ChildProcessError, ProcessLookupError):
                        pass
            if not children():
                break
            time.sleep(0.05)
        if not children():
            break
    process.wait(timeout=3)
    return {"ownedChildrenAtCleanup": len(initial), "ownedDescendantsGone": not children(),
            "leaderReaped": process.returncode is not None}


def limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def normalized(data):
    text = ANSI.sub('', data.decode('utf-8', 'replace'))
    text = text.replace('/owned/source', '[SOURCE]').replace('/owned', '[OWNED]').replace('/control', '[CONTROL]')
    if re.search(r'github_pat_[A-Za-z0-9_]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}', text):
        raise Hold('output_secret_shape_no_export')
    lines, redactions = [], 0
    for line in text.splitlines(keepends=True):
        # Do not export child environment dumps or startup/backtrace frames.
        if re.search(r'(?i)(?:\benviron(?:ment)?\s*[:={]|(?:API_KEY|AUTH_TOKEN|OAUTH_TOKEN|SECRET_ACCESS_KEY)\s*[:=]|stack backtrace:|traceback \(most recent call|^\s*\d+:\s|^\s*at (?:/|\[)|^\s*File ")', line):
            lines.append('[REDACTED_ENVIRONMENT_OR_STACK_LINE]\n'); redactions += 1
        else:
            # Any path from an unexpected operator home is an export hold.
            if re.search(r'/Users/|/home/(?!worker(?:/|\b))', line):
                raise Hold('unexpected_home_in_output_no_export')
            lines.append(line)
    return ''.join(lines).encode(), redactions


def environment(offline=False):
    env = {
        'HOME': '/owned/home', 'PATH': '/owned/toolchain/bin:/owned/bin:/usr/bin:/bin',
        'CARGO_HOME': '/owned/cargo-home', 'RUSTUP_HOME': '/owned/unused-rustup',
        'CARGO_TARGET_DIR': '/owned/target', 'TMPDIR': '/owned/tmp',
        'CARGO_BUILD_JOBS': '2', 'CARGO_INCREMENTAL': '0',
        'CARGO_PROFILE_DEV_DEBUG': '0', 'CARGO_PROFILE_TEST_DEBUG': '0',
        'CARGO_PROFILE_DEV_DEBUG_ASSERTIONS': 'true', 'CARGO_PROFILE_TEST_DEBUG_ASSERTIONS': 'true',
        'CORBANU_TEST_NO_NATIVE_KEYRING': '1', 'CARGO_NET_GIT_FETCH_WITH_CLI': 'true',
        'CARGO_NET_RETRY': '0', 'CARGO_TERM_COLOR': 'never', 'CARGO_HTTP_TIMEOUT': '60',
        'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_SYSTEM': '/dev/null', 'GIT_CONFIG_GLOBAL': '/dev/null',
        'GIT_CONFIG_COUNT': '2', 'GIT_CONFIG_KEY_0': 'gc.auto', 'GIT_CONFIG_VALUE_0': '0',
        'GIT_CONFIG_KEY_1': 'maintenance.auto', 'GIT_CONFIG_VALUE_1': 'false',
        'GIT_TERMINAL_PROMPT': '0', 'GIT_ASKPASS': '/usr/bin/false', 'SSH_ASKPASS': '/usr/bin/false',
        'GIT_SSH_COMMAND': '/usr/bin/false', 'NETRC': '/owned/empty-netrc',
        'XDG_CONFIG_HOME': '/owned/empty-config', 'CURL_HOME': '/owned/empty-config',
        'UV_CACHE_DIR': '/owned/uv-cache', 'UV_NO_CONFIG': '1', 'UV_PYTHON_DOWNLOADS': 'never',
        'DOTSLASH_CACHE': '/owned/dotslash-cache', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
        'PYTHONUNBUFFERED': '1', 'INSTA_UPDATE': 'no', 'INSTA_FORCE_PASS': '0',
    }
    env.update({k: os.environ[k] for k in MARKERS if k in os.environ})
    if offline:
        env.update({'CARGO_NET_OFFLINE': 'true', 'UV_OFFLINE': 'true'})
    return env


class Campaign:
    def __init__(self, mode):
        self.mode = mode
        self.env = environment(mode == 'qualify')
        self.rows = []
        self.total = 0
        self.deadline = time.monotonic() + (1500 if mode == 'acquire' else 5500)

    def run(self, label, argv, seconds=60, allow_failure=False):
        raw = ROOT / 'raw' / label
        raw.mkdir()
        files = {name: (raw / name).open('xb') for name in ('stdout', 'stderr', 'combined')}
        counts = {'stdout': 0, 'stderr': 0}
        started, process, failure, complete = time.monotonic(), None, None, False
        reaping, cleanup_failure = None, None
        clean = {'ownedDescendantsGone': False, 'leaderReaped': False}
        if children():
            raise Hold('unexpected_existing_child')
        with selectors.DefaultSelector() as select:
            try:
                process = subprocess.Popen(argv, cwd=SOURCE, env=self.env, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, preexec_fn=limits)
                for name, pipe in (('stdout', process.stdout), ('stderr', process.stderr)):
                    os.set_blocking(pipe.fileno(), False)
                    select.register(pipe, selectors.EVENT_READ, name)
                while process.poll() is None or select.get_map():
                    if time.monotonic() - started > seconds or time.monotonic() > self.deadline:
                        raise Hold('phase_deadline')
                    if shutil.disk_usage(ROOT).free < 10 * GIB:
                        raise Hold('running_disk_floor')
                    for key, _ in select.select(0.2):
                        data = os.read(key.fd, 65536)
                        if not data:
                            select.unregister(key.fileobj); key.fileobj.close(); continue
                        name = key.data
                        counts[name] += len(data); self.total += len(data)
                        if counts[name] > MAX_STREAM or self.total > MAX_TOTAL:
                            raise Hold('capture_bound')
                        files[name].write(data); files['combined'].write(data)
                process.wait()
                complete = True
                reaping = reap_exited_descendants()
                if reaping['remainingCount']:
                    raise Hold('child_survived_phase')
            except BaseException as error:
                failure = str(error) if isinstance(error, Hold) else 'controller_' + type(error).__name__
            finally:
                for key in list(select.get_map().values()):
                    select.unregister(key.fileobj); key.fileobj.close()
                if process:
                    try:
                        clean = cleanup(process)
                    except Exception:
                        cleanup_failure = 'owned_cleanup_incomplete'
                        failure = failure or cleanup_failure
                for handle in files.values():
                    handle.close()
        row = {'phase': label, 'exitCode': process.returncode if process else None,
               'seconds': round(time.monotonic() - started, 3), 'captureComplete': complete,
               'failureCode': failure, 'cleanupFailureCode': cleanup_failure,
               'cleanup': clean, 'completionDescendants': reaping,
               'argv': [normalized(a.encode())[0].decode() for a in argv], 'streams': {}}
        row['rawCaptures'] = {name: {'sha256': sha(raw / name), 'bytes': (raw / name).stat().st_size}
                              for name in ('stdout', 'stderr', 'combined')}
        self.rows.append(row)
        for name in ('stdout', 'stderr', 'combined'):
            path = raw / name
            if label == 'offline-dependency-preflight' and row['exitCode'] == 0 and name in ('stdout', 'combined'):
                metadata = json.loads((raw / 'stdout').read_text())
                compact = {'packageCount': len(metadata['packages']),
                    'resolvedNodeCount': len(metadata['resolve']['nodes']),
                    'machineInventoryOmitted': True, 'rawSha256': sha(raw / 'stdout')}
                data = (json.dumps(compact, sort_keys=True) + '\n').encode()
                if name == 'combined': data += (raw / 'stderr').read_bytes()
                try:
                    safe, redactions = normalized(data)
                except Hold as error:
                    row['exportFailureCode'] = str(error)
                    row['failureCode'] = row['failureCode'] or str(error)
                    raise Hold(label + '_capture_export_incomplete') from error
            else:
                try:
                    safe, redactions = normalized(path.read_bytes())
                except Hold as error:
                    row['exportFailureCode'] = str(error)
                    row['failureCode'] = row['failureCode'] or str(error)
                    raise Hold(label + '_capture_export_incomplete') from error
            # Phase names and fixed stream names are controller-owned allowlist entries.
            export = ROOT / 'public' / (label + '-' + name + '.log')
            export.write_bytes(safe)
            row['streams'][name] = {'rawSha256': sha(path), 'rawBytes': path.stat().st_size,
                'normalizedFile': export.name, 'normalizedSha256': sha(export),
                'normalizedBytes': export.stat().st_size, 'redactedLines': redactions}
        if failure or not complete or not clean['ownedDescendantsGone'] or not clean['leaderReaped']:
            raise Hold(label + '_incomplete')
        if row['exitCode'] and not allow_failure:
            raise Hold(label + '_nonzero')
        return raw, row

    def git(self, label, *args):
        raw, _ = self.run(label, ['/usr/bin/git', *args])
        return (raw / 'stdout').read_bytes()

    def verify_source(self, label, manifest, tools):
        if hasattr(self, 'immutable_tools'):
            for path, expected in self.immutable_tools.items():
                if sha(ROOT / path) != expected:
                    raise Hold('immutable_tool_changed')
        if self.git(label + '-head', 'rev-parse', 'HEAD').decode().strip() != manifest['baseCommit']:
            raise Hold('source_base_changed')
        for name, expected in tools['sourceInputs'].items():
            if sha(SOURCE / name) != expected:
                raise Hold('source_prerequisite_changed')
        for row in manifest['files']:
            if sha(SOURCE / row['path']) != row['candidateSha256']:
                raise Hold('candidate_file_changed')
        if self.git(label + '-untracked', 'ls-files', '--others', '--exclude-standard').strip():
            raise Hold('untracked_source')
        patch = self.git(label + '-diff', 'diff', '--binary', '--full-index', 'HEAD')
        if hashlib.sha256(patch).hexdigest() != manifest['patchSha256']:
            raise Hold('candidate_patch_changed')
        return hashlib.sha256(patch).hexdigest()


def acquire(campaign, manifest, tools, result):
    for row in manifest['files']:
        path = SOURCE / row['path']
        if row['originalSha256'] is None:
            if path.exists(): raise Hold('new_source_exists')
        elif sha(path) != row['originalSha256']:
            raise Hold('original_source_mismatch')
    if campaign.git('initial-head', 'rev-parse', 'HEAD').decode().strip() != manifest['baseCommit']:
        raise Hold('wrong_base')
    if campaign.git('initial-status', 'status', '--porcelain').strip():
        raise Hold('dirty_public_base')
    config_names = campaign.git('config-names', 'config', '--local', '--name-only', '--list').decode()
    if re.search(r'extraheader|credential|insteadof|sshcommand|include\.|hookspath|fsmonitor', config_names, re.I):
        raise Hold('source_auth_configuration')
    if (SOURCE / '.git/objects/info/alternates').exists():
        raise Hold('source_alternates')
    patch = CONTROL / 'change.patch'
    if sha(patch) != manifest['patchSha256']: raise Hold('payload_patch_hash')
    campaign.git('patch-check', 'apply', '--check', str(patch))
    campaign.git('patch-apply', 'apply', str(patch))
    new = [row['path'] for row in manifest['files'] if row['originalSha256'] is None]
    if new: campaign.git('intent-new-source', 'add', '--intent-to-add', '--', *new)
    campaign.verify_source('candidate-prepared', manifest, tools)
    for item in tools['archives']:
        dest = ROOT / 'downloads' / item['filename']
        campaign.run('fetch-' + item['id'], ['/usr/bin/curl', '-q', '--fail', '--silent', '--show-error',
            '--location', '--proto', '=https', '--proto-redir', '=https', '--retry', '0',
            '--connect-timeout', '20', '--max-time', '300', '--max-filesize', str(item['maxBytes']),
            '--output', str(dest), item['url']], 310)
        if dest.stat().st_size > item['maxBytes'] or sha(dest) != item['sha256']:
            raise Hold('public_archive_hash')
        if item['kind'] == 'v8-asset':
            campaign.env[item['variable']] = str(dest)
            continue
        unpack = ROOT / 'unpacked' / item['id']; unpack.mkdir()
        with tarfile.open(dest) as archive:
            members = archive.getmembers()
            if len(members) > 50000 or sum(x.size for x in members) > 2 * GIB:
                raise Hold('archive_expansion_bound')
            archive.extractall(unpack, filter='data')
        if item['kind'] == 'rust-component':
            installers = list(unpack.glob('*/install.sh'))
            if len(installers) != 1: raise Hold('rust_installer_identity')
            campaign.run('install-' + item['id'], ['/bin/sh', str(installers[0]),
                '--prefix=/owned/toolchain', '--disable-ldconfig'], 180)
        else:
            binaries = [p for p in unpack.rglob(item['binary']) if p.is_file() and not p.is_symlink()]
            if len(binaries) != 1: raise Hold('tool_binary_identity')
            dest = ROOT / 'bin' / item['binary']
            shutil.copyfile(binaries[0], dest); dest.chmod(0o700)
    result['toolIdentity'] = {}
    for name, expected in tools['versions'].items():
        path = shutil.which(name, path=campaign.env['PATH'])
        if not path: raise Hold('tool_missing')
        raw, _ = campaign.run('version-' + name, [path, '--version'])
        if expected not in (raw / 'stdout').read_text(): raise Hold('tool_version_mismatch')
        result['toolIdentity'][name] = {'expectedVersion': expected, 'sha256': sha(path)}
    # Native image prerequisites are versioned and hashed before Cargo can compile.
    result['nativePackagesSha256'] = sha('/native-packages.tsv')
    result['nativePackages'] = [line.split('\t') for line in Path('/native-packages.tsv').read_text().splitlines()]
    native = {}
    for name, args in {'python3': ['--version'], 'cc': ['--version'], 'c++': ['--version'],
                       'ld': ['--version'], 'pkg-config': ['--version'], 'bwrap': ['--version'],
                       'rg': ['--version'], 'clang': ['--version'], 'cmake': ['--version']}.items():
        path = shutil.which(name, path=campaign.env['PATH'])
        if not path: raise Hold('native_prerequisite_missing')
        raw, _ = campaign.run('native-' + name.replace('+', 'p'), [path, *args])
        native[name] = {'sha256': sha(path), 'versionFirstLine': (raw / 'stdout').read_text().splitlines()[0]}
    result['nativeTools'] = native
    campaign.run('native-libcap', ['/usr/bin/pkg-config', '--modversion', 'libcap'])
    campaign.run('native-openssl', ['/usr/bin/pkg-config', '--modversion', 'openssl'])
    campaign.run('formatter-buildifier-cache', ['/owned/bin/dotslash', str(SOURCE / 'tools/buildifier'), '--version'])
    campaign.run('formatter-scripts-cache', ['/owned/bin/uv', 'run', '--frozen', '--project', 'scripts', 'ruff', '--version'], 180)
    campaign.run('formatter-sdk-cache', ['/owned/bin/uv', 'run', '--frozen', '--project', 'sdk/python', '--only-group', 'format', 'ruff', '--version'], 180)
    campaign.run('fetch-locked', ['/owned/toolchain/bin/cargo', 'fetch', '--locked',
        '--manifest-path', str(SOURCE / 'codex-rs/Cargo.toml'), '--target', 'x86_64-unknown-linux-gnu'], 900)
    campaign.verify_source('after-acquisition', manifest, tools)
    if any((ROOT / 'target').iterdir()): raise Hold('acquisition_created_build_outputs')
    # Record complete byte identities of tools and public dependency caches for
    # an exact handoff to the network-disabled container. No cache contents export.
    inventory = {}
    for name in ('toolchain', 'bin', 'cargo-home', 'downloads', 'uv-cache', 'dotslash-cache'):
        for path in sorted((ROOT / name).rglob('*')):
            if path.is_file() and not path.is_symlink():
                inventory[str(path.relative_to(ROOT))] = sha(path)
    save(ROOT / 'acquired-inputs.json', inventory)
    result['acquiredInputsSha256'] = sha(ROOT / 'acquired-inputs.json')
    result['acquiredFileCount'] = len(inventory)


def nextest_config():
    original = (SOURCE / 'codex-rs/.config/nextest.toml').read_text()
    if '[profile.issue1177]' in original or '[store]' in original:
        raise Hold('nextest_profile_collision')
    # The ordinary local profile's existing 2x30-second case timeout is retained.
    return original + '''
[store]
dir = "/owned/target/nextest"
[profile.issue1177]
inherits = "local"
retries = 0
test-threads = 1
global-timeout = "300s"
[profile.issue1177.junit]
path = "junit.xml"
store-success-output = true
store-failure-output = true
report-skipped = "all"
'''


def classify(xml, combined):
    if len(xml) > 16 * 1024 * 1024 or b'<!DOCTYPE' in xml or b'<!ENTITY' in xml:
        raise Hold('junit_bound_or_dtd')
    root = ET.fromstring(xml)
    selected, excluded, seen = {}, set(), set()
    for case in root.iter('testcase'):
        name = case.get('name'); identity = (case.get('classname'), name)
        if identity in seen: raise Hold('duplicate_junit_identity')
        seen.add(identity)
        if case.get('classname') != 'codex-core::all': raise Hold('wrong_junit_binary')
        if name not in CASES:
            if case.find('skipped') is None or case.find('failure') is not None or case.find('error') is not None:
                raise Hold('unexpected_executed_case')
            excluded.add(name); continue
        if any(case.find(tag) is not None for tag in ('skipped', 'failure', 'error')):
            raise Hold('selected_case_not_pass')
        if any('rerun' in child.tag.lower() or 'flaky' in child.tag.lower() for child in case.iter()):
            raise Hold('selected_case_retried')
        if case.find('system-out') is None or case.find('system-err') is None:
            raise Hold('junit_body_capture_missing')
        body = '\n'.join(case.itertext())
        if re.search(r'(?i)\b(?:skipping|skipped)\b|capability[- ]unavailable', body):
            raise Hold('selected_body_skipped')
        if body.count(CASES[name]) != 1: raise Hold('selected_end_marker_missing_or_duplicate')
        seconds = float(case.get('time', '-1'))
        if not 0 <= seconds <= 60: raise Hold('selected_case_time_bound')
        selected[name] = {'status': 'PASS', 'seconds': seconds, 'endMarker': CASES[name], 'markerCount': 1}
    if set(selected) != set(CASES): raise Hold('selected_junit_cases_missing')
    text = ANSI.sub('', combined)
    summaries = list(re.finditer(r'(?m)^\s*Summary\s+\[[^\]]+\]\s+(\d+)\s+tests?\s+run:\s*(.+)$', text))
    if len(summaries) != 1: raise Hold('summary_missing_or_duplicate')
    summary = summaries[0]
    records = []
    for line in text[:summary.start()].splitlines():
        if not re.match(r'^\s*(PASS|FAIL|SKIP)\b', line): continue
        match = re.fullmatch(r'\s*(PASS|FAIL|SKIP)\s+\[[^\]]+\]\s+\(([^)]+)\)\s+(\S+)\s+(\S+)\s*', line)
        if not match: raise Hold('malformed_execution_record')
        state, ordinal, binary, name = match.groups()
        if binary != 'codex-core::all': raise Hold('wrong_execution_binary')
        if state == 'SKIP':
            if name in CASES or name not in excluded or not re.fullmatch(r'─+', ordinal):
                raise Hold('selected_or_unexplained_skip')
            continue
        index = re.fullmatch(r'\s*(\d+)/(\d+)\s*', ordinal)
        if state != 'PASS' or name not in CASES or index is None or tuple(map(int, index.groups())) != (len(records)+1, 4):
            raise Hold('execution_status_or_ordinal')
        records.append(name)
    if len(records) != 4 or set(records) != set(CASES): raise Hold('execution_identity_mismatch')
    if int(summary.group(1)) != 4 or not re.search(r'\b4 passed\b', summary.group(2)) or re.search(r'\b[1-9]\d* failed\b', summary.group(2)):
        raise Hold('summary_counts')
    if re.search(r'(?im)^\s*(?:TRY\s+\d|RETRY|FLAKY|TIMEOUT|TMPASS|LEAK|CANCEL)\b', text):
        raise Hold('retry_timeout_or_leak')
    if any(x in text for x in ('Skipping test because', 'Sandbox-dependent test skipped:', 'Skipping test in')):
        raise Hold('body_skip_message')
    if 'Test isolation: disposable profile; native keyring disabled (debug lane)' not in text:
        raise Hold('ordinary_wrapper_marker_missing')
    return {'selected': selected, 'executionOrder': records, 'selectedCount': 4,
            'selectedSkips': 0, 'retries': 0, 'filterExclusions': len(excluded),
            'intentCaseMap': {'I1177-01': [list(CASES)[0]], 'I1177-02': [list(CASES)[2]],
                'I1177-03': [list(CASES)[3]], 'I1177-04': [list(CASES)[3]], 'I1177-05': list(CASES)},
            'naturalBaselineFlakeReproduced': False, 'fullSuiteQualified': False}


def normalized_xml(data):
    """Normalize parsed text/attributes, then serialize with XML escaping."""
    if len(data) > 16 * 1024 * 1024 or b'<!DOCTYPE' in data or b'<!ENTITY' in data:
        raise Hold('junit_bound_or_dtd')
    root = ET.fromstring(data)
    redacted = 0
    for node in root.iter():
        for name, value in list(node.attrib.items()):
            safe, count = normalized(value.encode()); node.set(name, safe.decode()); redacted += count
        for field in ('text', 'tail'):
            value = getattr(node, field)
            if value is not None:
                safe, count = normalized(value.encode()); setattr(node, field, safe.decode()); redacted += count
    return ET.tostring(root, encoding='utf-8', xml_declaration=True), redacted


def capture_junit(result):
    """Retain success and failed-attempt XML before any outcome classification."""
    if 'junit' in result:
        return
    report = ROOT / 'target/nextest/issue1177/junit.xml'
    if not report.is_file():
        return
    row = {'rawSha256': sha(report), 'rawBytes': report.stat().st_size,
           'captureComplete': False, 'normalizedXmlParseable': False}
    result['junit'] = row
    if report.stat().st_size > 16 * 1024 * 1024:
        row['failureCode'] = 'junit_capture_bound'
        raise Hold('junit_capture_bound')
    data = report.read_bytes()
    try:
        safe, redacted = normalized_xml(data)
        filename = 'junit-selected.xml'
        row['normalizedXmlParseable'] = True
    except ET.ParseError:
        # Preserve incomplete failed-attempt diagnostics without claiming valid XML.
        safe, redacted = normalized(data)
        filename = 'junit-selected.xml.partial'
    path = ROOT / 'public' / filename
    path.write_bytes(safe)
    row.update({'normalizedFile': filename, 'normalizedSha256': sha(path),
                'normalizedBytes': len(safe), 'redactedLines': redacted, 'captureComplete': True})


def qualify(campaign, manifest, tools, result):
    acquired = json.loads((ROOT / 'acquired-inputs.json').read_text())
    for name, expected in acquired.items():
        if sha(ROOT / name) != expected: raise Hold('acquisition_handoff_hash')
    campaign.immutable_tools = {name: expected for name, expected in acquired.items()
        if name.split('/', 1)[0] in ('toolchain', 'bin', 'downloads')}
    # Refuse qualification under a present inherited network-disabled marker;
    # do not alter the marker, even if its value is zero.
    if 'CODEX_SANDBOX_NETWORK_DISABLED' in campaign.env:
        raise Hold('inherited_network_guard_preserved_no_execution')
    for item in tools['archives']:
        if item['kind'] == 'v8-asset': campaign.env[item['variable']] = str(ROOT / 'downloads' / item['filename'])
    result['sourceBefore'] = campaign.verify_source('qualification-before', manifest, tools)
    raw, _ = campaign.run('boundary-before', ['/usr/bin/python3', '-I', '-B', '/control/boundary_probe.py'], 45)
    result['boundaryBefore'] = json.loads((raw / 'stdout').read_text())
    if not all(x['passed'] for x in result['boundaryBefore'].values()): raise Hold('boundary_before_failed')
    _, orphan = campaign.run('owned-orphan-preflight', orphan_reaping_fixture_argv(), 10)
    if len(orphan['completionDescendants']['reapedExited']) != 1:
        raise Hold('owned_orphan_reaping_not_proven')
    _, formatted = campaign.run('full-format', ['/owned/bin/just', 'fmt'], 600, allow_failure=True)
    actual_format_diff = campaign.git('full-format-actual-diff', 'diff', '--binary', '--full-index', 'HEAD')
    result['formatDiffSha256'] = hashlib.sha256(actual_format_diff).hexdigest()
    if formatted['exitCode'] != 0: raise Hold('full_format_failed')
    campaign.verify_source('after-full-format', manifest, tools)
    # Offline metadata resolves the exact lock and transitive public dependencies,
    # but is explicitly not a build or behavioral pass.
    campaign.run('offline-dependency-preflight', ['/owned/toolchain/bin/cargo', 'metadata', '--locked', '--offline',
        '--format-version', '1', '--manifest-path', str(SOURCE / 'codex-rs/Cargo.toml'),
        '--filter-platform', 'x86_64-unknown-linux-gnu'], 120)
    result['capacityBeforeFreshBuildBytes'] = shutil.disk_usage(ROOT).free
    if result['capacityBeforeFreshBuildBytes'] < 30 * GIB: raise Hold('fresh_build_capacity_floor')
    common = ['/owned/bin/just', 'test', '-p', 'codex-core', '--test', 'all', '--locked', '--offline']
    raw, _ = campaign.run('compile-only', [*common, '-E', 'none()', '--no-tests', 'pass', '--retries', '0'], 2700)
    if re.search(r'(?m)^\s*(?:PASS|FAIL)\s+\[', (raw / 'combined').read_text()):
        raise Hold('compile_only_executed_test')
    campaign.verify_source('after-compile', manifest, tools)
    for name in tools['helperBinaries']:
        path = ROOT / 'target/debug' / name
        if not path.is_file() or not os.access(path, os.X_OK): raise Hold('mandatory_helper_binary_missing')
        result.setdefault('helperBinaries', {})[name] = {'sha256': sha(path), 'bytes': path.stat().st_size}
    campaign.run('clippy', ['/owned/bin/just', 'clippy', '-p', 'codex-core', '--locked', '--offline', '--', '-D', 'warnings'], 1800)
    campaign.verify_source('after-clippy', manifest, tools)
    config = ROOT / 'nextest.toml'; config.write_text(nextest_config())
    expression = ' | '.join('test(=' + name + ')' for name in CASES)
    report = ROOT / 'target/nextest/issue1177/junit.xml'
    if report.exists(): raise Hold('stale_junit')
    raw, row = campaign.run('four-selected-cases', [*common, '--config-file', str(config), '--profile', 'issue1177',
        '-E', expression, '--no-tests', 'fail', '--test-threads', '1', '--retries', '0', '--status-level', 'all',
        '--final-status-level', 'none', '--success-output', 'final', '--failure-output', 'final', '--color', 'never'],
        300, allow_failure=True)
    capture_junit(result)
    result['sourceAfter'] = campaign.verify_source('after-selected-cases', manifest, tools)
    if row['exitCode'] != 0: raise Hold('selected_wrapper_failed')
    if not report.is_file(): raise Hold('junit_missing')
    if not result['junit']['captureComplete'] or not result['junit']['normalizedXmlParseable']:
        raise Hold('junit_incomplete_or_invalid')
    result['cases'] = classify(report.read_bytes(), (raw / 'combined').read_text())
    binaries = [p for p in (ROOT / 'target/debug/deps').glob('all-*') if p.is_file() and os.access(p, os.X_OK)]
    if len(binaries) != 1: raise Hold('integration_binary_ambiguous')
    result['integrationBinary'] = {'sha256': sha(binaries[0]), 'bytes': binaries[0].stat().st_size}
    raw, _ = campaign.run('boundary-after', ['/usr/bin/python3', '-I', '-B', '/control/boundary_probe.py'], 45)
    result['boundaryAfter'] = json.loads((raw / 'stdout').read_text())
    if not all(x['passed'] for x in result['boundaryAfter'].values()): raise Hold('boundary_after_failed')
    result['qualified'] = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('acquire', 'qualify'))
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() != 'x86_64' or os.geteuid() == 0 or sys.version_info < (3, 12):
        raise Hold('worker_platform_or_identity')
    if os.environ.get('HOME') != '/owned/home': raise Hold('dedicated_home_required')
    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0: raise Hold('subreaper_required')
    campaign = Campaign(args.mode)
    markers = {k: (k in os.environ, os.environ.get(k)) for k in MARKERS}
    manifest = json.loads((CONTROL / 'source-manifest.json').read_text())
    tools = json.loads((CONTROL / 'tools-pins.json').read_text())
    result = {'schema': 'issue1177-hosted-worker-result-v1', 'mode': args.mode, 'qualified': False,
        'sourceBase': manifest['baseCommit'], 'sourcePatchSha256': manifest['patchSha256'],
        'controllerSha256': sha(__file__), 'commands': campaign.rows,
        'rawRetention': 'Ephemeral runner-owned raw captures; not uploaded and not claimed durably reconstructible.',
        'minimumFreshBuildBytes': 30 * GIB, 'runningStopFloorBytes': 10 * GIB}
    code = 1
    try:
        if shutil.disk_usage(ROOT).free < 30 * GIB: raise Hold('initial_capacity_floor')
        if args.mode == 'acquire': acquire(campaign, manifest, tools, result)
        else: qualify(campaign, manifest, tools, result)
        result['status'] = 'ACQUISITION_COMPLETE_NO_BUILD' if args.mode == 'acquire' else 'FOUR_CASES_PASSED'
        code = 0
    except BaseException as error:
        result['status'] = 'INCOMPLETE'
        result['failureCode'] = str(error) if isinstance(error, Hold) else 'controller_' + type(error).__name__
        result['qualified'] = False
    finally:
        if args.mode == 'qualify':
            try:
                capture_junit(result)
            except Exception:
                result['qualified'] = False; result['status'] = 'INCOMPLETE'; code = 1
                result['junitCaptureFailed'] = True
        result['ownedDescendantsGone'] = not children()
        result['inheritedMarkersPreserved'] = markers == {k: (k in campaign.env, campaign.env.get(k)) for k in MARKERS}
        if args.mode == 'qualify' and result['ownedDescendantsGone']:
            try:
                for name in ('home', 'tmp', 'empty-config'):
                    shutil.rmtree(ROOT / name)
                result['ownedHomeAndScratchRemoved'] = all(not (ROOT / name).exists() for name in ('home', 'tmp', 'empty-config'))
            except OSError:
                result['ownedHomeAndScratchRemoved'] = False
                result['ownedHomeCleanupFailureCode'] = 'owned_home_cleanup_failed'
                result.setdefault('failureCode', 'owned_home_cleanup_failed')
                result['qualified'] = False; result['status'] = 'INCOMPLETE'; code = 1
        if not result['ownedDescendantsGone'] or not result['inheritedMarkersPreserved']:
            result['qualified'] = False; result['status'] = 'INCOMPLETE'; code = 1
        save(ROOT / 'public' / (args.mode + '-result.json'), result)
        print(result['status'])
    return code


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print('WORKER_NOT_STARTED:' + (str(error) if isinstance(error, Hold) else type(error).__name__))
        sys.exit(1)


