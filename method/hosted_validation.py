#!/usr/bin/env python3
"""Prepared Linux/Windows Python-only validation. No Cargo or product execution.

Exact frozen sources are hash checked before use. Results distinguish Python
components, conditional Windows sockets, skips, and the unexecuted Rust gate.
"""
import concurrent.futures
import contextlib
import datetime
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import unittest
import urllib.request
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
PACKET = ROOT.parent
SOURCE = PACKET / 'source'
INTENT = ROOT
OUTPUT = PACKET / 'results' / 'acceptance'
BASELINE = PACKET / 'results' / 'baseline_isolated_rust_tests.py'
REAL_DIRECTORY = tempfile.TemporaryDirectory
REAL_POPEN = subprocess.Popen
START_ENV = dict(os.environ)
SOURCE_PINS = {
    'source/scripts/isolated_rust_tests.py': 'fa5033056664ef1e6db01ad99cacb1df975b89400649bf11d37e81f8beb12a38',
    'source/scripts/test_isolated_rust_tests.py': '5f919946c3d9022157d0f714d92bb3ff42b5eed706262fff07590627e71c2d20',
    'method/acceptance_probe.py': '193feaa4300adf8fb942580c4dba8a4f12afa8b9e9b115673d590f894ca3be69',
}
BASE_COMMIT = 'd8b98ba00e566c26c9b489f1b8eeebc4e2201cac'
BASELINE_SHA256 = '2376d36fae0943cbbf4a0caf58109b0dece03cb226983d1276216adc90d2447c'
CONTROL_NAMES = {key for key in START_ENV if key.startswith('CODEX_SANDBOX')}
PROCESS_LOCK = threading.Lock()
PROCESS_COUNT = 0


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def save(name, data):
    with (OUTPUT / name).open('x', encoding='utf-8') as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write('\n')


def audit(reports, phase):
    stream = io.StringIO()
    with contextlib.redirect_stdout(stream):
        probe.audit([str(report) for report in reports], phase)
    return json.loads(stream.getvalue())


def REAL_RUN(command, *, env, capture_output, text, timeout, check=False, **kwargs):
    """Run only the frozen Python child; retain bounded stdout/stderr and reap it."""
    global PROCESS_COUNT
    assert command[0] == sys.executable and command[1] == str(INTENT / 'acceptance_probe.py')
    assert capture_output and text and timeout <= 70
    assert all(env.get(key) == START_ENV[key] for key in CONTROL_NAMES)
    with PROCESS_LOCK:
        index = PROCESS_COUNT
        PROCESS_COUNT += 1
    stem = f'process-{index:02}'
    stdout_path, stderr_path = OUTPUT / (stem + '.stdout.log'), OUTPUT / (stem + '.stderr.log')
    started = time.monotonic()
    reason = None
    with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
        process = REAL_POPEN(command, env=env, stdout=stdout, stderr=stderr, **kwargs)
        try:
            while process.poll() is None:
                if time.monotonic() - started >= timeout:
                    reason = 'timeout'
                    break
                if stdout_path.stat().st_size + stderr_path.stat().st_size > 1048576:
                    reason = 'output-bound'
                    break
                time.sleep(0.02)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)
    save(stem + '.json', {'command':command,'exitCode':process.returncode,'stopReason':reason,
                         'elapsedSeconds':round(time.monotonic()-started,3),'directChildReaped':True,
                         'stdoutSha256':sha(stdout_path),'stderrSha256':sha(stderr_path)})
    if reason:
        raise RuntimeError('Frozen child stopped at ' + reason)
    output = subprocess.CompletedProcess(command, process.returncode, stdout_path.read_text(encoding='utf-8',errors='replace'), stderr_path.read_text(encoding='utf-8',errors='replace'))
    if check and output.returncode:
        raise subprocess.CalledProcessError(output.returncode, command, output.stdout, output.stderr)
    return output


def safe_environment():
    # No service token, credentials, or profile is copied into tested children.
    # Existing sandbox markers retain their exact presence and value.
    allowed = {'PATH','HOME','USERPROFILE','SYSTEMROOT','WINDIR','COMSPEC','PATHEXT','LANG','LC_ALL'}
    return {key:value for key,value in START_ENV.items() if key in allowed or key in CONTROL_NAMES}


def run_unit_tests():
    sys.path.insert(0, str(SOURCE / 'scripts'))
    before = dict(os.environ)
    with patch.dict(os.environ, safe_environment(), clear=True):
        suite = unittest.defaultTestLoader.discover(str(SOURCE / 'scripts'), pattern='test_isolated_rust_tests.py')
        with (OUTPUT / 'unittest.stdout.log').open('x',encoding='utf-8') as stdout, (OUTPUT / 'unittest.stderr.log').open('x',encoding='utf-8') as stderr, contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            run = unittest.TextTestRunner(stream=stderr,verbosity=2).run(suite)
    assert dict(os.environ) == before
    skipped = [{'test':test.id(),'reason':reason} for test,reason in run.skipped]
    result = {'testsRun':run.testsRun,'executed':run.testsRun-len(skipped),'failed':len(run.failures),
              'errors':len(run.errors),'skipped':skipped,'successfulExecutedSubset':run.wasSuccessful(),
              'skipIsPass':False,'ordinaryEquivalentCommand':['python','-m','unittest','discover','-s','source/scripts','-p','test_isolated_rust_tests.py','-v']}
    save('unittest-result.json',result)
    assert run.testsRun == 9 and run.wasSuccessful(), result
    assert len(skipped) == (1 if os.name == 'nt' else 0), result
    return result
def run_linux():
    with REAL_DIRECTORY(prefix='socket-caller-', dir='/tmp') as caller_base:
        caller = Path(caller_base)
        long = caller
        while len(os.fsencode(long)) <= 512:
            long /= 'd' * 72
            long.mkdir(mode=0o700)
        sentinel = long / 'caller-owned-sentinel'
        sentinel.write_text('synthetic-preserve', encoding='utf-8')
        unicode_long = caller / ('é' * 36)
        unicode_long.mkdir(mode=0o700)
        while len(os.fsencode(unicode_long)) <= 512:
            unicode_long /= 'é' * 36
            unicode_long.mkdir(mode=0o700)
        safe_parent = {key: value for key, value in START_ENV.items()
                       if key.startswith('CODEX_SANDBOX') or key in ('HOME', 'LANG', 'LC_ALL')}
        safe_parent.update(PATH='/usr/bin:/bin', CODEX_HOME=str(caller / 'synthetic-profile'),
                           CORBANU_HOME=str(caller / 'synthetic-profile'),
                           PFTERMINAL_HOME=str(caller / 'synthetic-profile'),
                           OPENAI_API_KEY='synthetic-key', ANTHROPIC_API_KEY='synthetic-key',
                           CORBANU_TEST_NO_NATIVE_KEYRING='1')
        (caller / 'synthetic-profile').mkdir(mode=0o700)
        assert all(safe_parent.get(k) == v for k, v in START_ENV.items() if k.startswith('CODEX_SANDBOX'))

        controls = {}
        for name, root, expected in [('short', caller, 'success'), ('long', long, 'path-too-long')]:
            actual = probe.exercise(str(root))
            save('control-' + name + '.json', {'kind': 'control', 'socket': actual})
            controls[name] = actual
            assert actual['status'] == expected, actual
        assert controls['long']['address_encoded_bytes'] > 512
        results['cases']['C01'] = {'Linux': 'PASS', 'macOS': 'previous separate receipt only', 'controls': controls}

        def invoke(module, label, aliases, outcome='success', release=None):
            report_path = OUTPUT / (label + '-child.json')
            owned = []
            dispatch = []
            environment = safe_parent | aliases
            before = None
            def fake_cargo(argv, *, cwd, env, check):
                assert argv == ['/synthetic/cargo', 'nextest', 'run', '--no-fail-fast', '-p', 'fixture']
                assert env['CORBANU_TEST_NO_NATIVE_KEYRING'] == '1'
                assert env['CARGO_PROFILE_DEV_DEBUG_ASSERTIONS'] == env['CARGO_PROFILE_TEST_DEBUG_ASSERTIONS'] == 'true'
                assert env['CORBANU_TEST_ACCOUNT_HOME'] == str(Path(env['CODEX_HOME']) / 'account')
                assert not any(k in env for k in ('CORBANU_HOME', 'PFTERMINAL_HOME', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY'))
                assert all(env.get(k) == v for k, v in START_ENV.items() if k.startswith('CODEX_SANDBOX'))
                root = Path(env['CODEX_HOME']).parent
                owned.append(str(root))
                command = [sys.executable, str(INTENT / 'acceptance_probe.py'), 'child', '--report', str(report_path),
                           '--owned-root', 'profile=env:CODEX_HOME', '--owned-root', 'scratch=env:TMPDIR',
                           '--owned-root', 'run=' + str(root), '--outcome', outcome]
                if release:
                    command += ['--release-file', str(release)]
                child = REAL_RUN(command, env=env, capture_output=True, text=True, timeout=70, check=False)
                (OUTPUT / (label + '-stdout.log')).write_text(child.stdout)
                (OUTPUT / (label + '-stderr.log')).write_text(child.stderr)
                dispatch.append(child.returncode)
                return subprocess.CompletedProcess(argv, child.returncode)
            with patch.dict(os.environ, environment, clear=True), patch.object(tempfile, 'tempdir', aliases.get('TMPDIR') or aliases.get('TEMP') or aliases.get('TMP') or str(caller)), \
                 patch.object(module.shutil, 'which', return_value='/synthetic/cargo'), \
                 patch.object(module.subprocess, 'run', side_effect=fake_cargo), \
                 patch.object(module, 'remove_leaked_mount_targets'):
                before = dict(os.environ)
                status = module.main(['-p', 'fixture'])
                assert before == dict(os.environ)
            assert dict(os.environ) == START_ENV
            assert len(dispatch) == len(owned) == 1
            assert all(not Path(p).exists() for p in owned)
            assert sentinel.read_text() == 'synthetic-preserve'
            report = json.loads(report_path.read_text())
            return {'exitCode': status, 'child': report, 'ownedRootsAbsent': True, 'parentEnvironmentUnchanged': True,
                    'callerSentinelPreserved': True, 'report': str(report_path)}

        inherited = dict.fromkeys(('TMPDIR', 'TMP', 'TEMP'), str(long))
        old = invoke(baseline, 'baseline-long', inherited)
        assert old['exitCode'] == 1 and old['child']['socket']['status'] == 'path-too-long'
        save('baseline-long-result.json', old)
        new = invoke(candidate, 'candidate-long', inherited)
        assert new['exitCode'] == 0 and new['child']['socket']['status'] == 'success'
        audit([OUTPUT / 'candidate-long-child.json'], 'cleaned')
        results['cases']['C02'] = {'LinuxPythonWrapper': 'PASS', 'macOS': 'previous separate receipt only', 'baseline': old, 'candidate': new,
                                   'limit': 'Actual wrapper API and real Python child path executed; Cargo/Rust dispatch replaced, so not C07 integration.'}
        short = invoke(candidate, 'candidate-short', dict.fromkeys(('TMPDIR','TMP','TEMP'), str(caller)))
        assert short['exitCode'] == 0
        results['cases']['C03'] = {'LinuxPythonWrapper': 'PASS', 'macOS': 'previous separate receipt only', 'result': short}

        # Concurrent runner.main invocations share a fixed synthetic environment; no
        # per-thread environment patching, and subprocess dispatch uses a unique index.
        concurrent_reports = [OUTPUT / f'concurrent-{i}-child.json' for i in range(2)]
        releases = [OUTPUT / f'concurrent-{i}.release' for i in range(2)]
        lock = threading.Lock()
        count = [0]
        def concurrent_cargo(argv, *, cwd, env, check):
            with lock:
                index = count[0]
                count[0] += 1
            root = str(Path(env['CODEX_HOME']).parent)
            command = [sys.executable, str(INTENT / 'acceptance_probe.py'), 'child', '--report', str(concurrent_reports[index]),
                       '--owned-root', 'profile=env:CODEX_HOME', '--owned-root', 'scratch=env:TMPDIR',
                       '--owned-root', 'run=' + root, '--release-file', str(releases[index])]
            child = REAL_RUN(command, env=env, capture_output=True, text=True, timeout=70)
            (OUTPUT / f'concurrent-{index}-stderr.log').write_text(child.stderr)
            return subprocess.CompletedProcess(argv, child.returncode)
        with patch.dict(os.environ, safe_parent | inherited, clear=True), patch.object(tempfile, 'tempdir', str(long)), \
             patch.object(candidate.shutil, 'which', return_value='/synthetic/cargo'), \
             patch.object(candidate.subprocess, 'run', side_effect=concurrent_cargo), \
             patch.object(candidate, 'remove_leaked_mount_targets'):
            before = dict(os.environ)
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(candidate.main, ['-p', 'fixture']) for _ in range(2)]
                try:
                    deadline = time.monotonic() + 20
                    while not all(p.exists() for p in concurrent_reports):
                        assert time.monotonic() < deadline, 'missing concurrency ready report'
                        time.sleep(0.05)
                    both_live = audit(concurrent_reports, 'live')
                    releases[0].touch()
                    # The index is assigned at child dispatch, so identify completion
                    # by the first report's roots rather than thread submission order.
                    report0 = json.loads(concurrent_reports[0].read_text())
                    deadline = time.monotonic() + 20
                    while any(Path(item['path']).exists() for item in report0['roots'].values()):
                        assert time.monotonic() < deadline, 'released invocation did not clean'
                        time.sleep(0.05)
                    first_cleaned = audit([concurrent_reports[0]], 'cleaned')
                    second_live = audit([concurrent_reports[1]], 'live')
                    assert sentinel.read_text() == 'synthetic-preserve'
                finally:
                    for release in releases:
                        release.touch(exist_ok=True)
                statuses = [future.result(timeout=20) for future in futures]
            assert before == dict(os.environ)
        assert dict(os.environ) == START_ENV and statuses == [0, 0]
        results['cases']['C04'] = {'LinuxPythonWrapper': 'PASS', 'macOS': 'previous separate receipt only', 'bothLive': both_live,
                                   'firstCleaned': first_cleaned, 'secondStillLive': second_live,
                                   'bothCleaned': audit(concurrent_reports, 'cleaned'), 'parentEnvironmentUnchanged': True}

        terminals = {}
        for outcome, expected in [('success',0), ('failure',19), ('exception',1)]:
            row = invoke(candidate, 'terminal-' + outcome, inherited, outcome)
            assert row['exitCode'] == expected
            row['audit'] = audit([OUTPUT / ('terminal-' + outcome + '-child.json')], 'cleaned')
            terminals[outcome] = row
        # Inject wrapper and setup exceptions at the existing unittest seams.
        for kind in ('launch-exception', 'setup-exception'):
            owned = []
            def factory(*args, **kwargs):
                resource = REAL_DIRECTORY(*args, **kwargs)
                owned.append(resource.name)
                return resource
            original_environment = candidate.test_environment
            def environment(parent, home):
                assert home.is_dir()
                if kind == 'setup-exception':
                    raise OSError('synthetic setup exception')
                return original_environment(parent, home)
            with patch.dict(os.environ, safe_parent | inherited, clear=True), \
                 patch.object(candidate.tempfile, 'TemporaryDirectory', side_effect=factory), \
                 patch.object(candidate.shutil, 'which', return_value='/synthetic/cargo'), \
                 patch.object(candidate.subprocess, 'run', side_effect=OSError('synthetic launch exception')) as launch, \
                 patch.object(candidate, 'test_environment', side_effect=environment), \
                 patch.object(candidate, 'remove_leaked_mount_targets'):
                before = dict(os.environ)
                try:
                    candidate.main(['-p', 'fixture'])
                    raise AssertionError('exception swallowed')
                except OSError as error:
                    assert str(error) == ('synthetic setup exception' if kind == 'setup-exception' else 'synthetic launch exception')
                assert before == dict(os.environ)
                if kind == 'setup-exception':
                    launch.assert_not_called()
            assert len(owned) == 1 and not Path(owned[0]).exists()
            terminals[kind] = {'status':'PASS', 'exceptionPropagated':True, 'ownedRoots':owned, 'ownedRootsAbsent':True}
        results['cases']['C05'] = {'LinuxPythonWrapper': 'PASS', 'macOS': 'previous separate receipt only', 'outcomes':terminals}

        refusals = ['--release','-r','-vr','-rj4','--cargo-profile=release','--config=x','--archive-file=old.tar.zst',
                    '--binaries-metadata=old.json','--cargo-metadata=old.json']
        save('C06-predeclared-contract.json', {'allowed':['-p','fixture'],'refusedBeforeProtectedAction':refusals,
             'flagOverrides':['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS'],
             'profileDestination':'No caller-selected profile destination option exists; inherited aliases are stripped or overwritten.',
             'source':'validate_debug_run and test_environment; docs/development/test-isolation.md ordinary debug lane'})
        refused_results = []
        for option in refusals:
            with patch.dict(os.environ, safe_parent, clear=True), patch.object(candidate.subprocess,'run') as run, \
                 patch.object(candidate.tempfile,'TemporaryDirectory') as resource:
                status = candidate.main([option])
                assert status == 2
                run.assert_not_called()
                resource.assert_not_called()
                refused_results.append({'option':option,'exitCode':status,'dispatches':0,'resources':0})
        for name in ('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS'):
            with patch.dict(os.environ, safe_parent | {name:'-Cdebug-assertions=no'},clear=True), patch.object(candidate.subprocess,'run') as run:
                assert candidate.main([]) == 2
                run.assert_not_called()
        results['cases']['C06'] = {'LinuxPythonWrapper':'PASS','macOS':'previous separate receipt only','refusals':refused_results,
                                  'allowedAndCredentialSuppression':'Verified during each child dispatch; no real credential store accessed.',
                                  'sandboxControlsPreserved':True,'limit':'No independent OS sandbox/security audit.'}
        results['cases']['C07'] = {'status':'NOT RUN','reason':'Native/Rust builds and execution excluded from this delegated task; real Rust fixture required on macOS and Linux.'}
        variants = {'all-long':inherited,'TMPDIR-only':{'TMPDIR':str(long)},'TMP-only':{'TMP':str(long)},
                    'TEMP-only':{'TEMP':str(long)},'no-aliases':{},'UTF8-all-long':dict.fromkeys(('TMPDIR','TMP','TEMP'),str(unicode_long))}
        variant_results = {}
        for label, aliases in variants.items():
            row = invoke(candidate,'variant-' + label, aliases)
            assert row['exitCode'] == 0
            variant_results[label] = {'status':'PASS','pythonEffectiveTemp':row['child']['roots']['effective-temp'],
                                      'socket':row['child']['socket'],'cleanup':row['ownedRootsAbsent'],
                                      'rustTempRoot':'NOT RUN'}
        results['cases']['C08'] = {'LinuxPythonWrapper':'PASS','macOS':'previous separate receipt only','RustTempResolution':'NOT RUN','variants':variant_results}
        results['cases']['C09'] = {'status':'NOT RUN','reason':'Windows is executed as the separate matrix job; this Linux artifact does not establish it.'}
        assert sentinel.read_text() == 'synthetic-preserve'
        results['callerSentinelSurvivedAllInvocations'] = True
        results['parentEnvironmentUnchanged'] = dict(os.environ) == START_ENV

"""Read-only, conservative owner/DACL inspection for an existing Windows directory.

Success describes a point-in-time owner/DACL snapshot of the opened directory.
It is not an AccessCheck simulation, a check of descendants/ancestors, or proof
against privileged access or concurrent security-descriptor changes. A nonzero
allow ACE applying to this directory is rejected for any unapproved SID even if
another ACE denies it or a condition might prevent its use.

No ACL, owner, privilege, file content, or token is modified; no process is run.
Windows execution is intentionally deferred to the prospective hosted harness.
"""

import ctypes
from ctypes import wintypes
import json
import os


class WindowsPrivacyError(RuntimeError):
    """A failed or inconclusive check; ``report`` contains JSON-safe evidence."""

    def __init__(self, report):
        self.report = report
        super().__init__("Windows directory privacy check failed: " + json.dumps(report, sort_keys=True))


def _windows_sid_string(raw):
    """Decode a bounded binary SID without account-name lookup or localization."""
    if len(raw) < 8 or raw[0] != 1 or raw[1] > 15:
        raise ValueError("invalid SID header")
    size = 8 + 4 * raw[1]
    if len(raw) < size:
        raise ValueError("truncated SID")
    authority = int.from_bytes(raw[2:8], "big")
    # Windows string SID syntax uses hex for identifier authorities above 2**32.
    authority_text = str(authority) if authority <= 0xFFFFFFFF else f"0x{authority:012x}"
    parts = ["S", "1", authority_text]
    parts.extend(str(int.from_bytes(raw[i:i + 4], "little")) for i in range(8, size, 4))
    return "-".join(parts), size


def _windows_ace_record(raw, index, allowed_sids, validated_owner=None):
    """Parse one bounded ACE; return evidence and any conservative blockers."""
    if len(raw) < 4 or int.from_bytes(raw[2:4], "little") != len(raw) or len(raw) % 4:
        raise ValueError("invalid ACE size")
    ace_type, flags = raw[:2]
    names = {
        0: "ACCESS_ALLOWED_ACE", 1: "ACCESS_DENIED_ACE",
        5: "ACCESS_ALLOWED_OBJECT_ACE", 6: "ACCESS_DENIED_OBJECT_ACE",
        9: "ACCESS_ALLOWED_CALLBACK_ACE", 10: "ACCESS_DENIED_CALLBACK_ACE",
        11: "ACCESS_ALLOWED_CALLBACK_OBJECT_ACE", 12: "ACCESS_DENIED_CALLBACK_OBJECT_ACE",
    }
    record = {
        "index": index, "type": ace_type, "type_name": names.get(ace_type, "UNSUPPORTED"),
        "flags": f"0x{flags:02x}", "size": len(raw),
        "inherited": bool(flags & 0x10), "inherit_only": bool(flags & 0x08),
    }
    # This flag makes the ACE inapplicable to this directory, including unknown
    # ACE types. Child-directory inheritance is outside this helper's scope.
    if flags & 0x08:
        record["disposition"] = "skipped_inherit_only"
        return record, []
    if ace_type not in names:
        record["disposition"] = "blocked_unsupported_type"
        return record, [{"code": "unsupported_effective_ace", "ace_index": index, "ace_type": ace_type}]
    if len(raw) < 16:
        raise ValueError("truncated access ACE")
    mask = int.from_bytes(raw[4:8], "little")
    record["mask"] = f"0x{mask:08x}"
    offset = 8
    if ace_type in (5, 6, 11, 12):
        object_flags = int.from_bytes(raw[8:12], "little")
        record["object_flags"] = f"0x{object_flags:08x}"
        if object_flags & ~3:
            raise ValueError("unsupported object ACE flags")
        offset = 12 + 16 * bool(object_flags & 1) + 16 * bool(object_flags & 2)
    sid, sid_size = _windows_sid_string(raw[offset:])
    record["sid"] = sid
    trailing = len(raw) - offset - sid_size
    if ace_type in (9, 10, 11, 12):
        record["callback_data_bytes"] = trailing
        record["condition_evaluated"] = False
    elif trailing:
        raise ValueError("unexpected trailing bytes in non-callback ACE")
    if ace_type in (1, 6, 10, 12):
        record["disposition"] = "deny_does_not_grant"
    elif mask == 0:
        record["disposition"] = "zero_mask_does_not_grant"
    elif sid == "S-1-3-4":
        # OWNER RIGHTS grants to the actual object owner, not a new principal.
        # Only a separately validated same-token default owner may resolve it.
        if validated_owner not in allowed_sids:
            record["disposition"] = "blocked_unvalidated_owner_rights"
            return record, [{"code": "owner_rights_without_validated_owner", "ace_index": index, "sid": sid}]
        record["resolved_sid"] = validated_owner
        record["disposition"] = "allowed_owner_rights_for_validated_owner"
    elif sid in allowed_sids:
        record["disposition"] = "allowed_trustee"
    else:
        record["disposition"] = "blocked_unapproved_trustee"
        return record, [{"code": "unapproved_effective_allow", "ace_index": index, "sid": sid, "mask": record["mask"]}]
    return record, []


def _windows_owner_record(user_sid, default_owner_sid, owner_sid):
    """Bind an observed owner to the same effective token without new principals."""
    allowed_sids = {user_sid, "S-1-5-18", "S-1-5-32-544"}
    report = {
        "current_user_sid": user_sid, "token_default_owner_sid": default_owner_sid,
        "owner_sid": owner_sid, "owner_matches_current_user": owner_sid == user_sid,
        "owner_matches_token_default_owner": owner_sid == default_owner_sid,
        "owner_in_existing_allowed_set": owner_sid in allowed_sids,
    }
    blockers = []
    if owner_sid != default_owner_sid:
        blockers.append({"code": "owner_does_not_match_token_default_owner", "owner_sid": owner_sid,
                         "token_default_owner_sid": default_owner_sid})
    if owner_sid not in allowed_sids:
        blockers.append({"code": "owner_not_in_existing_allowed_set", "owner_sid": owner_sid})
    report["validated_owner_sid"] = owner_sid if not blockers else None
    return report, blockers


def windows_privacy(path):
    """Return JSON-safe evidence, or raise WindowsPrivacyError with ``.report``.

    Owner must exactly equal TokenOwner from the same effective thread token
    (or process token if the thread has none), and belong to the unchanged set
    TokenUser, LocalSystem (S-1-5-18), Administrators (S-1-5-32-544). OWNER RIGHTS
    resolves only to this validated actual owner; effective nonzero allow ACEs
    remain restricted to that same set. No owner, DACL or token is modified.
    Missing/null DACLs, reparse-point targets, unsupported effective ACEs, malformed
    data and API/cleanup failures are explicit failures. An empty DACL is valid:
    it grants no access. No minimum current-user access rights are asserted.
    """
    report = {
        "ok": False, "path": os.fsdecode(os.fspath(path)),
        "method": "read_only_same_token_default_owner_and_conservative_dacl_allowlist_v2",
        "aces": [], "blockers": [],
        "scope": "opened directory only; point-in-time snapshot; not full effective-access evaluation",
    }
    if os.name != "nt":
        report["blockers"].append({"code": "unsupported_platform", "platform": os.name})
        raise WindowsPrivacyError(report)
    if "\x00" in report["path"]:
        report["blockers"].append({"code": "embedded_nul_path"})
        raise WindowsPrivacyError(report)

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    pointer = ctypes.c_void_p
    pp = ctypes.POINTER(pointer)
    dword_p = ctypes.POINTER(wintypes.DWORD)

    class TokenUser(ctypes.Structure):
        _fields_ = [("Sid", pointer), ("Attributes", wintypes.DWORD)]

    class TokenOwner(ctypes.Structure):
        _fields_ = [("Owner", pointer)]

    class FileInformation(ctypes.Structure):
        _fields_ = [
            ("Attributes", wintypes.DWORD), ("Creation", wintypes.FILETIME),
            ("Access", wintypes.FILETIME), ("Write", wintypes.FILETIME),
            ("VolumeSerial", wintypes.DWORD), ("SizeHigh", wintypes.DWORD),
            ("SizeLow", wintypes.DWORD), ("Links", wintypes.DWORD),
            ("IndexHigh", wintypes.DWORD), ("IndexLow", wintypes.DWORD),
        ]

    # Declare all pointer-width-sensitive signatures rather than relying on
    # ctypes' default int return type, which would truncate 64-bit handles.
    signatures = [
        (kernel, "GetCurrentProcess", [], wintypes.HANDLE),
        (kernel, "GetCurrentThread", [], wintypes.HANDLE),
        (kernel, "CloseHandle", [wintypes.HANDLE], wintypes.BOOL),
        (kernel, "LocalFree", [pointer], pointer),
        (kernel, "CreateFileW", [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, pointer, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE], wintypes.HANDLE),
        (kernel, "GetFileInformationByHandle", [wintypes.HANDLE, ctypes.POINTER(FileInformation)], wintypes.BOOL),
        (advapi, "OpenThreadToken", [wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL, ctypes.POINTER(wintypes.HANDLE)], wintypes.BOOL),
        (advapi, "OpenProcessToken", [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)], wintypes.BOOL),
        (advapi, "GetTokenInformation", [wintypes.HANDLE, ctypes.c_int, pointer, wintypes.DWORD, dword_p], wintypes.BOOL),
        (advapi, "GetSecurityInfo", [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, pp, pp, pp, pp, pp], wintypes.DWORD),
        (advapi, "IsValidSecurityDescriptor", [pointer], wintypes.BOOL),
        (advapi, "GetSecurityDescriptorDacl", [pointer, ctypes.POINTER(wintypes.BOOL), pp, ctypes.POINTER(wintypes.BOOL)], wintypes.BOOL),
        (advapi, "GetSecurityDescriptorControl", [pointer, ctypes.POINTER(wintypes.WORD), dword_p], wintypes.BOOL),
        (advapi, "IsValidSid", [pointer], wintypes.BOOL),
        (advapi, "GetLengthSid", [pointer], wintypes.DWORD),
        (advapi, "IsValidAcl", [pointer], wintypes.BOOL),
        (advapi, "GetAce", [pointer, wintypes.DWORD, pp], wintypes.BOOL),
    ]
    for library, name, arguments, result in signatures:
        function = getattr(library, name)
        function.argtypes = arguments
        function.restype = result

    class StopInspection(Exception):
        pass

    def stop(code, **details):
        report["blockers"].append({"code": code, **details})
        raise StopInspection()

    def check(success, operation):
        if not success:
            error = ctypes.get_last_error()
            stop("windows_api_error", operation=operation, winerror=error, message=ctypes.FormatError(error).strip())

    def read_sid(address, source):
        if not address or not advapi.IsValidSid(address):
            stop("invalid_sid", source=source)
        size = advapi.GetLengthSid(address)
        if not 8 <= size <= 68:
            stop("invalid_sid_length", source=source, size=size)
        return _windows_sid_string(ctypes.string_at(address, size))[0]

    token = wintypes.HANDLE()
    directory = None
    descriptor = pointer()
    try:
        # ERROR_NO_TOKEN alone permits falling back to the process's token.
        if advapi.OpenThreadToken(kernel.GetCurrentThread(), 0x0008, True, ctypes.byref(token)):
            report["token_source"] = "thread"
        else:
            error = ctypes.get_last_error()
            if error != 1008:
                stop("thread_token_query_failed", winerror=error, message=ctypes.FormatError(error).strip())
            check(advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)), "OpenProcessToken(TOKEN_QUERY)")
            report["token_source"] = "process"
        needed = wintypes.DWORD()
        success = advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        error = ctypes.get_last_error()
        if success or error != 122 or needed.value < ctypes.sizeof(TokenUser):
            stop("token_user_size_query_failed", winerror=error, returned_size=needed.value)
        token_buffer = ctypes.create_string_buffer(needed.value)
        check(advapi.GetTokenInformation(token, 1, token_buffer, len(token_buffer), ctypes.byref(needed)), "GetTokenInformation(TokenUser)")
        token_user = ctypes.cast(token_buffer, ctypes.POINTER(TokenUser)).contents
        user_sid = read_sid(token_user.Sid, "TokenUser")
        report["current_user_sid"] = user_sid
        allowed_sids = {user_sid, "S-1-5-18", "S-1-5-32-544"}
        report["allowed_sids"] = sorted(allowed_sids)
        # TokenOwner (class 4) is queried from the SAME read-only effective token.
        # The observed default is required; unreadable/malformed data never falls
        # back to TokenUser, Administrators, parent ownership or a historical run.
        owner_needed = wintypes.DWORD()
        success = advapi.GetTokenInformation(token, 4, None, 0, ctypes.byref(owner_needed))
        error = ctypes.get_last_error()
        if success or error != 122 or not ctypes.sizeof(TokenOwner) <= owner_needed.value <= 65536:
            stop("token_owner_size_query_failed", winerror=error, returned_size=owner_needed.value)
        owner_buffer = ctypes.create_string_buffer(owner_needed.value)
        check(advapi.GetTokenInformation(token, 4, owner_buffer, len(owner_buffer), ctypes.byref(owner_needed)), "GetTokenInformation(TokenOwner)")
        token_owner = ctypes.cast(owner_buffer, ctypes.POINTER(TokenOwner)).contents
        default_owner_sid = read_sid(token_owner.Owner, "TokenOwner")
        report["token_default_owner_sid"] = default_owner_sid

        # READ_CONTROL | FILE_READ_ATTRIBUTES, share all, OPEN_EXISTING,
        # FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT.
        # OPEN_REPARSE_POINT prevents following the final component; ancestors
        # are not checked. No write/delete/ownership rights are requested.
        directory = kernel.CreateFileW(report["path"], 0x00020080, 7, None, 3, 0x02200000, None)
        if directory == pointer(-1).value or directory is None:
            directory = None
            check(False, "CreateFileW(existing directory, read-only metadata)")
        file_info = FileInformation()
        check(kernel.GetFileInformationByHandle(directory, ctypes.byref(file_info)), "GetFileInformationByHandle")
        attributes = file_info.Attributes
        report["file_attributes"] = f"0x{attributes:08x}"
        report["file_identity"] = {"volume_serial": file_info.VolumeSerial, "file_index": (file_info.IndexHigh << 32) | file_info.IndexLow}
        if not attributes & 0x10:
            stop("target_is_not_directory")
        if attributes & 0x400:
            stop("target_is_reparse_point")
        owner, dacl = pointer(), pointer()
        error = advapi.GetSecurityInfo(directory, 1, 0x00000005, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor))
        if error:
            stop("windows_api_error", operation="GetSecurityInfo(OWNER|DACL)", winerror=error, message=ctypes.FormatError(error).strip())
        if not descriptor.value or not advapi.IsValidSecurityDescriptor(descriptor):
            stop("invalid_security_descriptor")
        owner_sid = read_sid(owner, "directory_owner")
        owner_record, owner_blockers = _windows_owner_record(user_sid, default_owner_sid, owner_sid)
        report.update(owner_record)
        report["blockers"].extend(owner_blockers)
        present, defaulted = wintypes.BOOL(), wintypes.BOOL()
        check(advapi.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)), "GetSecurityDescriptorDacl")
        control, revision = wintypes.WORD(), wintypes.DWORD()
        check(advapi.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)), "GetSecurityDescriptorControl")
        report.update(dacl_present=bool(present.value), dacl_null=not bool(dacl.value), dacl_defaulted=bool(defaulted.value), dacl_protected=bool(control.value & 0x1000), security_descriptor_control=f"0x{control.value:04x}")
        if not present.value or not dacl.value:
            stop("missing_or_null_dacl_grants_unrestricted_access")
        if not advapi.IsValidAcl(dacl):
            stop("invalid_dacl")
        acl_header = ctypes.string_at(dacl, 8)
        acl_size = int.from_bytes(acl_header[2:4], "little")
        ace_count = int.from_bytes(acl_header[4:6], "little")
        report.update(acl_revision=acl_header[0], acl_size=acl_size, ace_count=ace_count)
        if acl_header[0] not in (2, 4) or acl_size < 8:
            stop("unsupported_acl_header")
        for index in range(ace_count):
            ace = pointer()
            check(advapi.GetAce(dacl, index, ctypes.byref(ace)), f"GetAce({index})")
            if not ace.value or not dacl.value + 8 <= ace.value <= dacl.value + acl_size - 4:
                stop("ace_header_outside_acl", ace_index=index)
            header = ctypes.string_at(ace, 4)
            ace_size = int.from_bytes(header[2:4], "little")
            if ace_size < 4 or ace.value + ace_size > dacl.value + acl_size:
                stop("ace_outside_acl", ace_index=index, ace_size=ace_size)
            try:
                record, blockers = _windows_ace_record(ctypes.string_at(ace, ace_size), index, allowed_sids, report["validated_owner_sid"])
            except ValueError as error:
                stop("malformed_or_unsupported_ace", ace_index=index, message=str(error))
            report["aces"].append(record)
            report["blockers"].extend(blockers)
    except StopInspection:
        pass
    except Exception as error:
        report["blockers"].append({"code": "inspection_error", "exception": type(error).__name__, "message": str(error)})
    finally:
        if descriptor.value and kernel.LocalFree(descriptor):
            report["blockers"].append({"code": "security_descriptor_free_failed", "winerror": ctypes.get_last_error()})
        for name, handle in (("directory", directory), ("token", token)):
            if handle and not kernel.CloseHandle(handle):
                report["blockers"].append({"code": "handle_close_failed", "handle_kind": name, "winerror": ctypes.get_last_error()})
    if report["blockers"]:
        raise WindowsPrivacyError(report)
    report["ok"] = True
    return report


def run_windows():
    # The fresh hosted runner's scratch drive is an explicit prerequisite. Only
    # a securely allocated unique child is owned; the drive is never removed.
    drive = Path(START_ENV['RUNNER_TEMP']).anchor
    assert drive and Path(drive).is_dir()
    with REAL_DIRECTORY(prefix='cb-', dir=drive) as caller_base:
        caller = Path(caller_base)
        windows_privacy(caller)
        sentinel = caller / 'caller-owned-sentinel'
        sentinel.write_text('synthetic-preserve',encoding='utf-8')
        long = caller
        long_blocker = None
        try:
            while len(os.fsencode(long)) <= 512:
                long /= 'd' * 72
                long.mkdir(mode=0o700)
            (long / 'filesystem-control').write_text('synthetic',encoding='utf-8')
        except OSError as error:
            long_blocker = {'status':'BLOCKED','reason':'Long caller path not usable under this runner filesystem policy',
                            'errorType':type(error).__name__,'message':str(error)}
        short_socket = probe.exercise(str(caller))
        save('windows-short-socket-control.json',{'kind':'control','socket':short_socket})
        socket_supported = short_socket['status'] == 'success'
        long_socket = probe.exercise(str(long)) if long_blocker is None else None
        save('windows-conditional-socket.json',{'short':short_socket,'long':long_socket,
             'shortCapability':'DEMONSTRATED' if socket_supported else 'UNAVAILABLE_OR_BLOCKED',
             'longSocketPass':False if long_socket is None else long_socket['status']=='success',
             'limit':'Portable no-socket child results never count as socket passes. Windows long-root socket-path limits are retained, not repaired by this POSIX-only source change.'})
        parent = safe_environment()
        parent.update(CODEX_HOME=str(caller/'synthetic-profile'),CORBANU_HOME=str(caller/'synthetic-profile'),
                      PFTERMINAL_HOME=str(caller/'synthetic-profile'),OPENAI_API_KEY='synthetic-key',
                      ANTHROPIC_API_KEY='synthetic-key',CORBANU_TEST_NO_NATIVE_KEYRING='1')
        (caller/'synthetic-profile').mkdir(mode=0o700)
        records = []
        variants = [('short',caller)] + ([('long',long)] if long_blocker is None else [])
        for label, inherited_root in variants:
            for outcome, expected in [('success',0),('failure',19),('exception',1)]:
                report_path = OUTPUT / f'windows-{label}-{outcome}-child.json'
                release = OUTPUT / f'windows-{label}-{outcome}.release'
                # Long Windows paths do not acquire a new AF_UNIX guarantee.
                # Use an actual socket only if this exact direct-root control
                # passed; otherwise record portable filesystem behavior only.
                use_socket = socket_supported if label=='short' else bool(long_socket and long_socket['status']=='success')
                captured = []
                def dispatch(argv, *, cwd, env, check):
                    assert argv == ['/synthetic/cargo','nextest','run','--no-fail-fast','-p','fixture']
                    assert env['CORBANU_TEST_NO_NATIVE_KEYRING']=='1'
                    assert not any(key in env for key in ('CORBANU_HOME','PFTERMINAL_HOME','OPENAI_API_KEY','ANTHROPIC_API_KEY'))
                    assert all(env.get(key)==START_ENV[key] for key in CONTROL_NAMES)
                    owned = Path(env['CODEX_HOME']).parent
                    captured.append(str(owned))
                    command=[sys.executable,str(INTENT/'acceptance_probe.py'),'child','--report',str(report_path),
                             '--owned-root','profile=env:CODEX_HOME','--owned-root','scratch=env:TMPDIR',
                             '--owned-root','run='+str(owned),'--outcome',outcome,'--release-file',str(release)]
                    if not use_socket:
                        command.append('--portable-no-socket')
                    child=REAL_RUN(command,env=env,capture_output=True,text=True,timeout=70)
                    return subprocess.CompletedProcess(argv,child.returncode)
                aliases=dict.fromkeys(('TMPDIR','TMP','TEMP'),str(inherited_root))
                with patch.dict(os.environ,parent|aliases,clear=True), patch.object(tempfile,'tempdir',str(inherited_root)), \
                     patch.object(candidate.shutil,'which',return_value='/synthetic/cargo'), \
                     patch.object(candidate.subprocess,'run',side_effect=dispatch), patch.object(candidate,'remove_leaked_mount_targets'):
                    before=dict(os.environ)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        future=pool.submit(candidate.main,['-p','fixture'])
                        try:
                            deadline=time.monotonic()+20
                            while not report_path.exists():
                                if future.done():
                                    future.result()
                                    raise AssertionError('Child finished without a readiness report')
                                assert time.monotonic()<deadline,'Windows child readiness timeout'
                                time.sleep(0.05)
                            report=json.loads(report_path.read_text())
                            expected_socket='success' if use_socket else 'portable-no-socket'
                            assert report['socket']['status']==expected_socket, report['socket']
                            privacy={name:windows_privacy(item['path']) for name,item in report['roots'].items()}
                            live=audit([report_path],'live')
                        finally:
                            release.touch(exist_ok=True)
                        status=future.result(timeout=20)
                    assert dict(os.environ)==before
                assert dict(os.environ)==START_ENV and status==expected
                assert len(captured)==1 and not Path(captured[0]).exists()
                assert sentinel.read_text()=='synthetic-preserve'
                records.append({'variant':label,'outcome':outcome,'exitCode':status,'privacy':privacy,'liveAudit':live,
                                'cleanedAudit':audit([report_path],'cleaned'),'socketStatus':report['socket']['status'],
                                'socketPassed':report['socket']['status']=='success','parentEnvironmentUnchanged':True,
                                'callerSentinelPreserved':True})
        # The unchanged candidate unittest suite separately executes wrapper
        # setup/launch exceptions and preserves their exceptions/owned cleanup.
        results['cases']['C09']={'WindowsPythonWrapper':'BLOCKED' if long_blocker else 'PASS',
            'ordinaryWorkflowSeam':'Actual runner.main with fake Cargo dispatch to an actual standard-library Python child; not a Rust workflow.',
            'variants':records,'longFilesystemBlocker':long_blocker,
            'socketCapability':'DEMONSTRATED_SHORT' if socket_supported else 'UNAVAILABLE_OR_BLOCKED',
            'socketUnavailableIsPass':False,'privacyMethod':'Read-only same-token default-owner binding and conservative DACL allowlist; OWNER RIGHTS resolves only to validated owner. System/admin privileges are not denied.',
            'setupAndLaunchExceptions':'See unittest-result.json; executed separately from child exceptions.'}
        for key in ('C01','C02','C03','C04','C05','C06','C08'):
            results['cases'][key]={'status':'NOT RUN','reason':'Unix case belongs to Linux/macOS receipts; Windows observations are C09 only.'}
        results['cases']['C07']={'status':'NOT RUN','reason':'Real Rust macOS+Linux workflow is a separately prepared required gate.'}
        results['callerSentinelSurvivedAllInvocations']=sentinel.read_text()=='synthetic-preserve'
        results['parentEnvironmentUnchanged']=dict(os.environ)==START_ENV
        if long_blocker:
            raise RuntimeError('Windows long-path filesystem prerequisite unavailable; short results retained')


def main():
    global baseline, candidate, probe, results
    expected_platform = sys.argv[1] if len(sys.argv)==2 else None
    assert expected_platform in ('linux','win32') and sys.platform==expected_platform
    assert platform.python_version()=='3.13.7', platform.python_version()
    assert platform.machine().lower() in ('amd64','x86_64'),platform.machine()
    for relative,expected in SOURCE_PINS.items():
        assert sha(PACKET/relative)==expected,relative
    assert START_ENV.get('GITHUB_ACTIONS')=='true','Run only on the declared disposable hosted runner.'
    OUTPUT.mkdir(parents=True,mode=0o700,exist_ok=False)
    (SOURCE/'codex-rs').mkdir(exist_ok=False)
    results={'schema':'socket-tmp-hosted-python-v2','platform':sys.platform,'python':platform.python_version(),
             'startedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'sourceBase':BASE_COMMIT,
             'candidateSourceHashes':SOURCE_PINS,'harnessSha256':sha(__file__),
             'runtime':{'pythonExecutableSha256':sha(sys.executable),'pythonExecutable':sys.executable,
                        'platform':platform.platform(),'machine':platform.machine(),
                        'runnerImageOS':START_ENV.get('ImageOS'),'runnerImageVersion':START_ENV.get('ImageVersion'),
                        'runId':START_ENV.get('GITHUB_RUN_ID'),'runAttempt':START_ENV.get('GITHUB_RUN_ATTEMPT'),
                        'workflowCommit':START_ENV.get('GITHUB_SHA')},
             'sandboxControlsPreserved':True,'cases':{},'rustExecuted':False,'fullFrozenAcceptanceQualified':False}
    try:
        with (OUTPUT/'harness.stdout.log').open('x',encoding='utf-8') as stdout, (OUTPUT/'harness.stderr.log').open('x',encoding='utf-8') as stderr, contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            url=f'https://raw.githubusercontent.com/CorbanuCore/CorbanuTerminal/{BASE_COMMIT}/scripts/isolated_rust_tests.py'
            with urllib.request.urlopen(url,timeout=30) as response:
                data=response.read(65537)
            assert len(data)<=65536 and hashlib.sha256(data).hexdigest()==BASELINE_SHA256
            BASELINE.write_bytes(data)
            baseline=load('baseline_runner',BASELINE)
            candidate=load('candidate_runner',SOURCE/'scripts/isolated_rust_tests.py')
            probe=load('frozen_probe',INTENT/'acceptance_probe.py')
            results['unittest']=run_unit_tests()
            if sys.platform=='linux':
                run_linux()
            else:
                run_windows()
        results['pythonComponentMethodStatus']='PASS'
    except BaseException as error:
        results['pythonComponentMethodStatus']='FAIL_OR_BLOCKED'
        results['error']={'type':type(error).__name__,'message':str(error)}
        if isinstance(error,WindowsPrivacyError):
            results['windowsPrivacyBlocker']=error.report
        with (OUTPUT/'failure.traceback.log').open('x',encoding='utf-8') as stream:
            traceback.print_exc(file=stream)
    finally:
        results['finishedAt']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        results['sourceIntegrityAfter']={relative:sha(PACKET/relative) for relative in SOURCE_PINS}
        results['sourceUnchanged']=results['sourceIntegrityAfter']==SOURCE_PINS
        results['parentEnvironmentUnchanged']=dict(os.environ)==START_ENV
        if not results['sourceUnchanged'] or not results['parentEnvironmentUnchanged']:
            results['pythonComponentMethodStatus']='FAIL_OR_BLOCKED'
        results['remainingRequiredGates']=['C07 real Rust ordinary wrapper execution on macOS and Linux.',
            'C08 independent actual Rust temp-root resolution for each Unix alias variant.',
            'Combine distinct host receipts without treating skips or conditional socket unavailability as passes.']
        save('result.json',results)
        retained={str(p.relative_to(PACKET/'results')):{'sha256':sha(p),'bytes':p.stat().st_size}
                  for p in (PACKET/'results').rglob('*') if p.is_file()}
        save('retained-artifact-files.json',retained)
    print(json.dumps({'platform':sys.platform,'status':results['pythonComponentMethodStatus'],
                      'rustExecuted':False,'fullFrozenAcceptanceQualified':False}))
    return 0 if results['pythonComponentMethodStatus']=='PASS' else 1


if __name__=='__main__':
    raise SystemExit(main())
