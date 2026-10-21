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
from worker import compare_snapshots, link_records, metadata_inventory, safe_extract, snapshot_selected, snapshot_tree, tree_entries


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
        result = json.loads((self.root / 'pr1161-format-evidence/controller-result.json').read_text())
        self.assertEqual(result['failureCode'], 'global_deadline')
        self.assertEqual(result['cleanup']['failure'], 'OSError')
        self.assertFalse(result['ownedStateRemoved'])
        self.assertTrue((temp / 'pr1161-format-1').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
