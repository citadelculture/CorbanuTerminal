"""Ordinary test attempt plus separately attributed executable/list evidence."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from hosted_controls import digest, write_json


def select_library_binary(target):
    candidates = []
    for path in (target / 'debug/deps').glob('codex_tui-*'):
        if path.is_file() and not path.is_symlink() and os.access(path, os.X_OK):
            with path.open('rb') as stream:
                if stream.read(4) == b'\x7fELF':
                    candidates.append(path.resolve())
    if len(candidates) != 1:
        raise RuntimeError('Cannot uniquely attribute codex-tui lib ELF: ' + str(candidates))
    return candidates[0]


def validate_list(metadata, original, original_hash, expected_tests, kind="lib"):
    suites = [suite for suite in metadata['rust-suites'].values()
              if suite.get('package-name') == 'codex-tui' and suite.get('kind') == kind]
    if len(suites) != 1:
        raise RuntimeError('Expected one codex-tui lib suite in exact nextest metadata')
    suite = suites[0]
    checks = {'binary-name': 'codex_tui' if kind == 'lib' else 'codex-tui', 'kind': kind,
              'status': 'listed', 'build-platform': 'target'}
    if any(suite.get(key) != value for key, value in checks.items()):
        raise RuntimeError('Unexpected codex-tui library suite identity')
    if kind == 'lib' and suite.get('binary-id') != 'codex-tui':
        raise RuntimeError('Unexpected codex-tui library binary ID')
    binary_id = suite.get('binary-id')
    if not isinstance(binary_id, str) or not binary_id or metadata['rust-suites'].get(binary_id) != suite:
        raise RuntimeError('Metadata suite key and attributed binary ID differ')
    path = Path(suite['binary-path']).resolve(strict=True)
    if path != original or digest(path) != original_hash:
        raise RuntimeError('Metadata/list changed the test executable after the ordinary attempt')
    matches = [name for name, case in suite['testcases'].items()
               if case.get('filter-match', {}).get('status') == 'matches'
               and case.get('kind') == 'test' and not case.get('ignored')]
    if sorted(matches) != sorted(expected_tests):
        raise RuntimeError('Metadata does not select exactly the frozen selected names')
    return suite


def main():
    assert sys.dont_write_bytecode, "Native controller requires PYTHONDONTWRITEBYTECODE=1"
    label, kind, expression, *expected_tests = sys.argv[1:]
    if (label, kind) not in (("compile", "bin"), ("generate", "lib")):
        raise RuntimeError("Only stage1 compile/capture entry points are supported")
    if (kind == "bin" and (expression != "none()" or expected_tests)) or (kind == "lib" and len(expected_tests) != 2):
        raise RuntimeError("Invalid stage1 selector/count")
    target_args = ["--lib"] if kind == "lib" else ["--bin", "codex-tui"]
    output = Path('/out')
    target = Path('/scratch/target')
    command = ['just', 'test', '-p', 'codex-tui', *target_args, '--locked', '--offline',
               '--retries', '0', '--test-threads', '1', '--status-level', 'all',
               '--final-status-level', 'all', '--success-output', 'immediate',
               '--failure-output', 'immediate', '-E', expression]
    if kind == 'bin':
        command += ['--no-tests', 'pass']
    subprocess.run(['python3', '/method/container-preflight.py'], check=True)
    attempt = subprocess.run(command, check=False)
    record = {'sourceCommit': os.environ['SOURCE_COMMIT'], 'ordinaryCommand': command,
              'ordinaryExitCode': attempt.returncode, 'metadataIsSeparateListingNotTestQualification': True,
              'kind': kind, 'compileOnly': kind == 'bin', 'selectedTests': expected_tests}
    try:
        # Preserve the original bytes before any post-run metadata command can build.
        original = select_library_binary(target)
        original_hash = digest(original)
        retained = output / (label + '-codex-tui-' + kind + '-test')
        if shutil.disk_usage(output).free - original.stat().st_size < 8 * 1024**3:
            raise RuntimeError('Binary preservation would cross continuous disk reserve')
        shutil.copy2(original, retained)
        if digest(retained) != original_hash:
            raise RuntimeError('Retained test executable differs from original bytes')
        record.update(originalPath=str(original), retainedPath=retained.name,
                      sha256=original_hash, bytes=retained.stat().st_size)
        # This invokes --list only after the ordinary test; use the unchanged
        # repository environment helper for the same disposable-profile hygiene.
        spec = importlib.util.spec_from_file_location('ordinary_wrapper', '/src/scripts/isolated_rust_tests.py')
        wrapper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(wrapper)
        # A none() binary filter may omit discovery entirely. This separate
        # metadata-only command lists the exact bin; its pinned main has no
        # test declarations. It never executes a test case.
        list_expression = 'all()' if kind == 'bin' else expression
        list_args = ['-p', 'codex-tui', *target_args, '--locked', '--offline', '-E', list_expression]
        wrapper.validate_debug_run(list_args, dict(os.environ))
        with tempfile.TemporaryDirectory(prefix='issue1290-metadata-') as temporary:
            fixture = Path(temporary) / 'profile'
            fixture.mkdir()
            environment = wrapper.test_environment(dict(os.environ), fixture)
            list_command = ['cargo', 'nextest', 'list', '--message-format', 'json', *list_args]
            with (output / (label + '-nextest-list.json')).open('xb') as stdout, (output / (label + '-nextest-list.log')).open('xb') as stderr:
                listing = subprocess.run(list_command, stdout=stdout, stderr=stderr,
                                         env=environment, timeout=180, check=False)
            record.update(metadataCommand=list_command, metadataExitCode=listing.returncode)
            if listing.returncode:
                raise RuntimeError('Separate nextest metadata listing failed')
        metadata = json.loads((output / (label + '-nextest-list.json')).read_text())
        suite = validate_list(metadata, original, original_hash, expected_tests, kind)
        record['metadataBinaryId'] = suite['binary-id']
        record['metadataAndPreservedBinaryMatch'] = True
    except BaseException as error:
        record['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        write_json(output / (label + '-executed-binary.json'), record)
    return attempt.returncode


if __name__ == '__main__':
    raise SystemExit(main())
