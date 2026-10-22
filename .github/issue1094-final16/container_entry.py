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


def validate_list(metadata, original, original_hash, expected_tests):
    suites = [suite for suite in metadata['rust-suites'].values()
              if suite.get('package-name') == 'codex-tui' and suite.get('kind') == 'lib']
    if len(suites) != 1:
        raise RuntimeError('Expected one codex-tui lib suite in exact nextest metadata')
    suite = suites[0]
    checks = {'binary-id': 'codex-tui', 'binary-name': 'codex_tui', 'kind': 'lib',
              'status': 'listed', 'build-platform': 'target'}
    if any(suite.get(key) != value for key, value in checks.items()):
        raise RuntimeError('Unexpected codex-tui library suite identity')
    path = Path(suite['binary-path']).resolve(strict=True)
    if path != original or digest(path) != original_hash:
        raise RuntimeError('Metadata/list changed the test executable after the ordinary attempt')
    selected = {name: case for name, case in suite['testcases'].items()
                if case.get('filter-match', {}).get('status') == 'matches'}
    if len(set(expected_tests)) != len(expected_tests):
        raise RuntimeError('Frozen test inventory contains duplicates')
    if any(case.get('kind') != 'test' or case.get('ignored') for case in selected.values()):
        raise RuntimeError('Selected metadata contains an ignored or non-test case')
    if sorted(selected) != sorted(expected_tests):
        raise RuntimeError('Metadata does not select exactly the frozen test inventory')
    return suite


def main():
    assert sys.dont_write_bytecode, "Native controller requires PYTHONDONTWRITEBYTECODE=1"
    label, expression = sys.argv[1:]
    binding = json.loads(Path('/method/final-binding.json').read_text())
    expected_tests = binding['expectedTests']
    assert len(expected_tests) == 16 and binding['state'] == 'ROOT_ACCEPTED_FULLFMT_FINAL_SOURCE_BOUND'
    assert os.environ.get('INSTA_UPDATE') == 'no' and os.environ.get('INSTA_FORCE_PASS') == '0'
    output = Path('/out')
    target = Path('/scratch/target')
    command = ['just', 'test', '-p', 'codex-tui', '--lib', '--locked', '--offline',
               '--retries', '0', '--test-threads', '1', '--status-level', 'all',
               '--final-status-level', 'all', '--success-output', 'immediate',
               '--failure-output', 'immediate', '-E', expression]
    subprocess.run(['python3', '/method/container-preflight.py'], check=True)
    attempt = subprocess.run(command, check=False)
    record = {'sourceCommit': os.environ['SOURCE_COMMIT'], 'ordinaryCommand': command,
              'ordinaryExitCode': attempt.returncode, 'metadataIsSeparateListingNotTestQualification': True}
    try:
        # Preserve the original bytes before any post-run metadata command can build.
        original = select_library_binary(target)
        original_hash = digest(original)
        retained = output / (label + '-codex-tui-lib-test')
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
        list_args = ['-p', 'codex-tui', '--lib', '--locked', '--offline', '-E', expression]
        wrapper.validate_debug_run(list_args, dict(os.environ))
        with tempfile.TemporaryDirectory(prefix='issue1094-metadata-') as temporary:
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
        validate_list(metadata, original, original_hash, expected_tests)
        record['metadataAndPreservedBinaryMatch'] = True
    except BaseException as error:
        record['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        write_json(output / (label + '-executed-binary.json'), record)
    return attempt.returncode


if __name__ == '__main__':
    raise SystemExit(main())
