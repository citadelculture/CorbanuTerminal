#!/usr/bin/env python3
"""Offline toy/mock controls: no network, formatter, native builds or tests."""
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import controller
from controller import admitted, child_environment, complete, digest, identity_check, write
import evidence
from evidence import audit_bytes, export_audited
from worker import compare_candidate_snapshots, expanded_entries, require_absent, verify_index_inventory, compare_snapshots, link_records, metadata_inventory, safe_extract, snapshot_selected, snapshot_tree, tree_entries


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def link_fixture(self):
        path = self.root / 'fixture/link'
        path.parent.mkdir()
        target = '/never-open-external-fixture'
        path.symlink_to(target)
        record = {'path': 'fixture/link', 'mode': '120000', 'blob': 'a' * 40, 'targetSha256': hashlib.sha256(target.encode()).hexdigest(), 'targetBytes': len(target.encode())}
        row = ('120000 blob ' + 'a' * 40 + '\tfixture/link\0').encode()
        return path, record, row

    def test_known_external_link_never_opened_or_resolved(self):
        path, record, raw = self.link_fixture()
        with patch.object(Path, 'open', side_effect=AssertionError('open forbidden')), patch.object(Path, 'resolve', side_effect=AssertionError('resolve forbidden')):
            self.assertEqual(link_records(self.root, raw, [record]), [record])
            self.assertEqual(snapshot_tree(self.root, tree_entries(raw), [record])['fixture/link']['type'], 'symlink')

    def test_changed_link_target_rejected(self):
        path, record, raw = self.link_fixture()
        path.unlink(); path.symlink_to('/changed')
        with self.assertRaisesRegex(RuntimeError, 'identity_mismatch'):
            link_records(self.root, raw, [record])

    def test_unknown_and_missing_link_rejected(self):
        path, record, raw = self.link_fixture()
        with self.assertRaisesRegex(RuntimeError, 'unexpected_tracked_symlink'):
            link_records(self.root, raw, [])
        with self.assertRaisesRegex(RuntimeError, 'inventory_mismatch'):
            link_records(self.root, b'', [record])

    def test_link_replaced_with_file_rejected(self):
        path, record, raw = self.link_fixture()
        path.unlink(); path.write_text('/never-open-external-fixture')
        with self.assertRaisesRegex(RuntimeError, 'symlink_replaced'):
            link_records(self.root, raw, [record])

    def test_tree_submodule_and_duplicate_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'unsupported_tree_entry'):
            tree_entries(b'160000 commit a\tmodule\0')
        with self.assertRaisesRegex(RuntimeError, 'duplicate'):
            tree_entries(b'100644 blob a\ta\0' * 2)

    def archive(self, name, kind=None, target=''):
        path = self.root / 'tool.tar'
        with tarfile.open(path, 'w') as archive:
            member = tarfile.TarInfo(name)
            if kind:
                member.type = kind; member.linkname = target; archive.addfile(member)
            else:
                member.size = 2; archive.addfile(member, io.BytesIO(b'ok'))
        return path

    def test_safe_archive_preserves_regular_bytes(self):
        safe_extract(self.archive('tool/bin/just'), self.root / 'out')
        self.assertEqual((self.root / 'out/tool/bin/just').read_bytes(), b'ok')

    def test_archive_parent_escape_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'path_escape'):
            safe_extract(self.archive('../escape'), self.root / 'out')

    def test_archive_external_symlink_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'absolute_link'):
            safe_extract(self.archive('x', tarfile.SYMTYPE, '/outside'), self.root / 'out')

    def test_archive_escaping_hardlink_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'link_escape'):
            safe_extract(self.archive('x', tarfile.LNKTYPE, '../outside'), self.root / 'out')

    def test_snapshot_exact_bytes(self):
        source = self.root / 'src'; source.mkdir(); (source / 'a.rs').write_bytes(b'fn public_fixture() {}\n')
        records = snapshot_selected(source, self.root, 'formatted-source', {'a.rs': 'input-hash'})
        self.assertEqual((self.root / 'formatted-source/a.rs').read_bytes(), (source / 'a.rs').read_bytes())
        self.assertEqual(records['a.rs']['sha256'], digest(source / 'a.rs'))

    def test_snapshot_symlink_and_parent_rejected(self):
        source = self.root / 'src'; source.mkdir(); (source / 'a.rs').symlink_to('/never-open')
        with self.assertRaisesRegex(RuntimeError, 'unsafe_selected_source'):
            snapshot_selected(source, self.root, 'capture', {'a.rs': 'x'})
        (source / 'sub').symlink_to('/never-open-dir')
        with self.assertRaisesRegex(RuntimeError, 'subject_parent_not_directory'):
            snapshot_selected(source, self.root, 'capture', {'sub/a.rs': 'x'})

    def snapshots(self):
        before = {'a.rs': {'type': 'regular', 'mode': '100644', 'bytes': 1, 'sha256': 'a'}, 'lock': {'type': 'regular', 'mode': '100644', 'bytes': 1, 'sha256': 'b'}}
        return before, json.loads(json.dumps(before))

    def test_only_selected_format_delta_accepted(self):
        before, after = self.snapshots(); after['a.rs']['sha256'] = 'formatted'
        self.assertEqual(compare_snapshots(before, after, ['a.rs']), ['a.rs'])
        after['lock']['sha256'] = 'drift'
        with self.assertRaisesRegex(RuntimeError, 'unexpected_tracked_source_delta'):
            compare_snapshots(before, after, ['a.rs'])

    def test_candidate_type_mode_and_inventory_changes_rejected(self):
        for mutation in ['type', 'mode', 'inventory']:
            before, after = self.snapshots()
            if mutation == 'inventory': del after['lock']
            else: after['a.rs'][mutation] = 'changed'
            with self.assertRaises(RuntimeError): compare_snapshots(before, after, ['a.rs'])

    def test_metadata_cache_is_not_compiled_output(self):
        target = self.root / 'target'; target.mkdir(); (target / '.rustc_info.json').write_text('{}')
        self.assertEqual(metadata_inventory(target)[0]['path'], '.rustc_info.json')
        (target / 'libsubject.rlib').write_bytes(b'compiled')
        with self.assertRaisesRegex(RuntimeError, 'unexpected_cargo_target_output'): metadata_inventory(target)

    def test_metadata_symlink_rejected(self):
        target = self.root / 'target'; target.mkdir(); (target / '.rustc_info.json').symlink_to('/never-open')
        with self.assertRaisesRegex(RuntimeError, 'unexpected_cargo_target_output'): metadata_inventory(target)

    def admitted_packet(self):
        (self.root / 'x').write_bytes(b'public'); manifest = {'files': [{'path': 'x', 'bytes': 6, 'sha256': digest(self.root / 'x')}]}
        write(self.root / 'packet-manifest.json', manifest)
        admission = {'approved': True, 'reviewReceiptSha256': 'a' * 64, 'packetManifestSha256': digest(self.root / 'packet-manifest.json')}
        return admission, manifest

    def test_unapproved_and_changed_manifest_rejected(self):
        a, m = self.admitted_packet(); admitted(self.root, a, m)
        with self.assertRaisesRegex(RuntimeError, 'method_not_admitted'): admitted(self.root, {**a, 'approved': False}, m)
        with self.assertRaisesRegex(RuntimeError, 'manifest_mismatch'): admitted(self.root, {**a, 'packetManifestSha256': 'b' * 64}, m)
        (self.root / 'x').write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError, 'hash_mismatch'): admitted(self.root, a, m)

    def test_manifest_duplicate_and_symlink_parent_rejected(self):
        a, m = self.admitted_packet()
        with self.assertRaisesRegex(RuntimeError, 'duplicate'): admitted(self.root, a, {'files': m['files'] * 2})
        (self.root / 'link').symlink_to('/never-open')
        with self.assertRaisesRegex(RuntimeError, 'parent_not_directory'): admitted(self.root, a, {'files': [{**m['files'][0], 'path': 'link/x'}]})

    def identity(self):
        return {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'citadelculture/CorbanuTerminal', 'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': 'refs/heads/' + controller.BRANCH, 'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_RUN_NUMBER': '1', 'GITHUB_WORKFLOW_REF': 'citadelculture/CorbanuTerminal/' + controller.WORKFLOW + '@refs/heads/' + controller.BRANCH, 'ImageOS': 'ubuntu24', 'ImageVersion': '20261021.1'}

    def test_exact_identity_accepted_wrong_run_branch_attempt_refused(self):
        identity_check(self.identity())
        for key, value in [('GITHUB_RUN_ATTEMPT', '2'), ('GITHUB_RUN_NUMBER', '2'), ('GITHUB_REF', 'refs/heads/main'), ('GITHUB_EVENT_NAME', 'workflow_dispatch'), ('GITHUB_REPOSITORY', 'another/repo'), ('GITHUB_WORKFLOW_REF', 'wrong')]:
            with self.assertRaises(RuntimeError): identity_check({**self.identity(), key: value})

    def test_child_has_owned_home_no_tokens_and_preserves_guards(self):
        parent = {'HOME': '/not-to-forward', 'GH_TOKEN': 'synthetic-token', 'ACTIONS_RUNTIME_TOKEN': 'synthetic-token', 'CODEX_SANDBOX': 'seatbelt', 'CODEX_SANDBOX_NETWORK_DISABLED': '1', 'CODEX_SANDBOX_EXTRA': 'deny'}
        env = child_environment(parent, self.root)
        self.assertEqual(env['HOME'], str(self.root / 'home'))
        self.assertNotIn('GH_TOKEN', env); self.assertNotIn('ACTIONS_RUNTIME_TOKEN', env)
        for key in parent:
            if key.startswith('CODEX_SANDBOX'): self.assertEqual(env[key], parent[key])

    def test_unknown_cleanup_never_completes(self):
        result = {'workerExitCode': 0, 'cleanup': {'ownedGroupGone': False, 'directChildReaped': True}, 'ownedStateRemoved': True}
        self.assertFalse(complete({'completed': True}, result))
        result['cleanup']['ownedGroupGone'] = True
        self.assertTrue(complete({'completed': True}, result))
        result['ownedStateRemoved'] = False
        self.assertFalse(complete({'completed': True}, result))

    def test_group_permission_denial_is_not_absence(self):
        child = SimpleNamespace(pid=123, wait=lambda timeout: 1)
        with patch.object(controller, 'group_state', return_value='unknown'), patch.object(controller.os, 'killpg', side_effect=AssertionError('must not signal')):
            r = controller.cleanup(child)
        self.assertFalse(r['ownedGroupGone']); self.assertEqual(r['failure'], 'owned_group_state_unknown')

    def raw_public(self):
        raw = self.root / 'raw'; public = self.root / 'public'; raw.mkdir(); public.mkdir()
        return raw, public

    def test_raw_logs_preserved_and_normalized_with_separate_hashes(self):
        raw, public = self.raw_public(); data = b'\x1b[31mpublic\x1b[0m\r\nentry\0'
        (raw / '01-version.log').write_bytes(data)
        result = {'completed': True}; export_audited(raw, public, result, {})
        self.assertEqual((public / '01-version.log').read_bytes(), data)
        self.assertEqual((public / 'normalized/01-version.log.txt').read_bytes(), b'public\nentry\\0')
        self.assertTrue(result['completed'])

    def test_unlisted_orphan_withheld_final_receipt_still_written(self):
        raw, public = self.raw_public(); (raw / 'unknown.txt').write_text('orphan'); (raw / '01-version.log').write_text('safe')
        result = {'completed': True, 'failureCode': 'primary_failure'}; export_audited(raw, public, result, {})
        self.assertFalse(result['completed']); self.assertEqual(result['failureCode'], 'primary_failure')
        self.assertFalse((public / 'unknown.txt').exists()); self.assertTrue((public / 'controller-result.json').exists())

    def test_secret_raw_withheld_without_erasing_hash(self):
        raw, public = self.raw_public(); data = b'GH_TOKEN=synthetic-sensitive-value\n'; (raw / '01-tool.log').write_bytes(data)
        result = {'completed': True}; export_audited(raw, public, result, {})
        self.assertFalse(result['completed']); self.assertFalse((public / '01-tool.log').exists())
        self.assertEqual(result['evidenceAudit']['withheld'][0]['sha256'], hashlib.sha256(data).hexdigest())

    def test_public_synthetic_windows_path_is_allowed(self):
        self.assertTrue(audit_bytes(b'fixture D:/Users/fixture and C:\\Users\\fixture'))

    def test_aggregate_export_bound_blocks_completion(self):
        raw, public = self.raw_public(); (raw / '01-tool.log').write_bytes(b'x' * 16)
        with patch.object(evidence, 'MAX_EVIDENCE_BYTES', 2 * 1024**2 + 20):
            result = {'completed': True}; export_audited(raw, public, result, {})
        self.assertFalse(result['completed']); self.assertFalse((public / '01-tool.log').exists())

    def test_primary_deadline_survives_cleanup_exception_with_final_receipt(self):
        method = self.root / 'method'; method.mkdir(); temp = self.root / 'runner'; temp.mkdir()
        for name, value in [('admission.json', {}), ('packet-manifest.json', {}), ('source-pins.json', {'candidateFiles': {}})]: write(method / name, value)
        class FakeChild:
            pid = 999999
            returncode = None
            def poll(self): return None
        env = {**self.identity(), 'RUNNER_TEMP': str(temp)}
        with patch.object(controller, 'HERE', method), patch.object(controller, 'admitted'), patch.object(controller.sys, 'platform', 'linux'), patch.object(controller.os, 'uname', return_value=SimpleNamespace(machine='x86_64')), patch.object(controller.os, 'getuid', return_value=1000), patch.object(controller.os, 'geteuid', return_value=1000), patch.dict(controller.os.environ, env, clear=True), patch.object(controller.subprocess, 'check_output', return_value=b'a' * 40 + b'\n'), patch.object(controller.subprocess, 'Popen', return_value=FakeChild()), patch.object(controller.shutil, 'disk_usage', return_value=SimpleNamespace(free=16 * 1024**3)), patch.object(controller, 'WORK_SECONDS', -1), patch.object(controller, 'cleanup', side_effect=OSError('mock cleanup failure')):
            self.assertEqual(controller.main(), 1)
        result = json.loads((self.root / 'pr951-format-evidence/controller-result.json').read_text())
        self.assertEqual(result['failureCode'], 'global_deadline')
        self.assertEqual(result['cleanup']['failure'], 'OSError')
        self.assertFalse(result['ownedStateRemoved'])
        self.assertTrue((temp / 'pr951-format-1').exists())



class AddedFileControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'; self.source.mkdir()
        self.export = self.root / 'export'; self.export.mkdir()
        self.data = b'fn added_fixture() {}\n'
        self.name = 'module/new.rs'
        self.pin = {'mode': '100644', 'blob': hashlib.sha1(b'blob ' + str(len(self.data)).encode() + b'\0' + self.data).hexdigest(), 'sha256': hashlib.sha256(self.data).hexdigest(), 'bytes': len(self.data)}
        self.additions = {self.name: self.pin}
        self.pins = {'candidateFiles': {self.name: self.pin['sha256']}, 'allowedChangedFiles': [self.name], 'addedRegularFiles': self.additions}

    def tearDown(self):
        self.temp.cleanup()

    def test_baseline_absence_record_without_fabricated_file(self):
        records = snapshot_selected(self.source, self.export, 'base-source', self.pins['candidateFiles'], self.additions)
        self.assertEqual(records[self.name], {'type': 'absent', 'reason': 'explicit_added_regular_file'})
        self.assertFalse((self.export / 'base-source' / self.name).exists())
        result = {'completed': True}; public = self.root / 'public'; public.mkdir()
        export_audited(self.export, public, result, self.pins['candidateFiles'])
        self.assertTrue(result['completed'])
        self.assertEqual(json.loads((public / 'base-source.json').read_text()), records)

    def test_unexpected_preexisting_regular_refused(self):
        path = self.source / self.name; path.parent.mkdir(); path.write_bytes(self.data)
        with self.assertRaisesRegex(RuntimeError, 'added_path_preexists'):
            snapshot_selected(self.source, self.export, 'base-source', self.pins['candidateFiles'], self.additions)

    def test_unexpected_preexisting_dangling_symlink_refused(self):
        path = self.source / self.name; path.parent.mkdir(); path.symlink_to('/never-open')
        with patch.object(Path, 'open', side_effect=AssertionError('must not open')):
            with self.assertRaisesRegex(RuntimeError, 'added_path_preexists'):
                require_absent(self.source, self.name)

    def test_symlink_parent_and_escaping_path_refused(self):
        (self.source / 'module').symlink_to('/never-open')
        with self.assertRaisesRegex(RuntimeError, 'added_parent_not_directory'):
            require_absent(self.source, self.name)
        for name in ('../escape', '/escape'):
            with self.assertRaisesRegex(RuntimeError, 'added_path_escape'):
                require_absent(self.source, name)

    def test_absence_cannot_be_exported_as_formatted_success(self):
        with self.assertRaisesRegex(RuntimeError, 'invalid_absent_source_scope'):
            snapshot_selected(self.source, self.export, 'formatted-source', self.pins['candidateFiles'], self.additions)

    def test_exact_absent_to_added_transition(self):
        path = self.source / self.name; path.parent.mkdir(); path.write_bytes(self.data)
        entries = expanded_entries([], self.pins)
        after = snapshot_tree(self.source, entries, [])
        self.assertEqual(compare_candidate_snapshots({}, after, [self.name], self.additions), [self.name])
        self.assertEqual(snapshot_selected(self.source, self.export, 'candidate-source', self.pins['candidateFiles'])[self.name]['sha256'], self.pin['sha256'])

    def test_extra_added_path_and_missing_added_file_refused(self):
        after = {self.name: {'type': 'regular', 'mode': '100644', 'bytes': len(self.data), 'sha256': self.pin['sha256']}}
        for mutated in ({}, {**after, 'extra.rs': after[self.name]}):
            with self.assertRaisesRegex(RuntimeError, 'candidate_inventory_changed'):
                compare_candidate_snapshots({}, mutated, [self.name], self.additions)

    def test_added_bytes_mode_or_type_change_refused(self):
        expected = {'type': 'regular', 'mode': '100644', 'bytes': len(self.data), 'sha256': self.pin['sha256']}
        for key, value in [('type', 'symlink'), ('mode', '100755'), ('bytes', 0), ('sha256', 'wrong')]:
            with self.assertRaisesRegex(RuntimeError, 'added_file_identity_mismatch'):
                compare_candidate_snapshots({}, {self.name: {**expected, key: value}}, [self.name], self.additions)

    def test_changed_existing_inventory_still_refused(self):
        before = {'kept': {'type': 'regular', 'mode': '100644', 'bytes': 1, 'sha256': 'x'}}
        new = {self.name: {'type': 'regular', 'mode': '100644', 'bytes': len(self.data), 'sha256': self.pin['sha256']}}
        with self.assertRaisesRegex(RuntimeError, 'candidate_inventory_changed'):
            compare_candidate_snapshots(before, new, [self.name], self.additions)
        with self.assertRaisesRegex(RuntimeError, 'unexpected_tracked_source_delta'):
            compare_candidate_snapshots(before, {**new, 'kept': {**before['kept'], 'sha256': 'drift'}}, [self.name], self.additions)

    def test_added_pin_scope_mode_and_parent_conflict_refused(self):
        with self.assertRaisesRegex(RuntimeError, 'added_path_in_base_tree'):
            expanded_entries([{'path': self.name, 'mode': '100644', 'blob': 'a' * 40}], self.pins)
        with self.assertRaisesRegex(RuntimeError, 'added_parent_file_conflict'):
            expanded_entries([{'path': 'module', 'mode': '120000', 'blob': 'a' * 40}], self.pins)
        with self.assertRaisesRegex(RuntimeError, 'added_pin_invalid'):
            expanded_entries([], {**self.pins, 'addedRegularFiles': {self.name: {**self.pin, 'mode': '120000'}}})
        with self.assertRaisesRegex(RuntimeError, 'added_pin_scope'):
            expanded_entries([], {**self.pins, 'candidateFiles': {}})

    def test_exact_intent_index_extra_or_changed_entry_refused(self):
        empty = hashlib.sha1(b'blob 0\0').hexdigest()
        base = [{'path': 'kept', 'mode': '100644', 'blob': 'a' * 40}]
        raw = ('100644 ' + 'a' * 40 + ' 0\tkept\0' + '100644 ' + empty + ' 0\t' + self.name + '\0').encode()
        verify_index_inventory(raw, base, self.additions)
        for mutant in (raw + b'100644 a 0\textra\0', raw.replace(b' 0\tkept', b' 1\tkept'), raw.replace(('a' * 40).encode(), ('b' * 40).encode()), raw + raw):
            with self.assertRaises(RuntimeError): verify_index_inventory(mutant, base, self.additions)

    def test_actual_toy_git_intent_add_is_in_diff_and_not_untracked(self):
        import subprocess, os
        def git(*args):
            git_binary = '/Library/Developer/CommandLineTools/usr/bin/git' if controller.sys.platform == 'darwin' else 'git'
            return subprocess.check_output([git_binary, '-c', 'gc.auto=0', '-C', str(self.source), *args], stderr=subprocess.PIPE,
                env={**os.environ, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_TERMINAL_PROMPT': '0'}, timeout=10)
        git('init', '-q')
        (self.source / 'kept').write_bytes(b'kept\n'); git('add', 'kept')
        git('-c', 'user.name=Public Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-q', '-m', 'Synthetic baseline')
        base = tree_entries(git('ls-tree', '-r', '-z', git('write-tree').decode().strip()))
        patchfile = self.root / 'new.patch'
        patchfile.write_text('diff --git a/module/new.rs b/module/new.rs\nnew file mode 100644\n--- /dev/null\n+++ b/module/new.rs\n@@ -0,0 +1 @@\n+fn added_fixture() {}\n')
        git('apply', '--check', str(patchfile)); git('apply', str(patchfile))
        self.assertEqual(git('ls-files', '--others', '--exclude-standard', '-z'), (self.name + '\0').encode())
        git('add', '--intent-to-add', '--', self.name)
        verify_index_inventory(git('ls-files', '--stage', '-z'), base, self.additions)
        self.assertFalse(git('ls-files', '--others', '--exclude-standard', '-z'))
        diff = git('diff', '--full-index', '--binary').decode()
        self.assertIn('new file mode 100644', diff); self.assertIn('+fn added_fixture() {}', diff)
        self.assertEqual(compare_candidate_snapshots(snapshot_tree(self.source, base, []), snapshot_tree(self.source, expanded_entries(base, self.pins), []), [self.name], self.additions), [self.name])


if __name__ == '__main__':
    unittest.main(verbosity=2)
