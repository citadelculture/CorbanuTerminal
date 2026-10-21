#!/usr/bin/env python3
"""Synthetic exporter controls only: no product commands or binary execution."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

import evidence as e


def elf(payload=b''):
    data = bytearray(64)
    data[:6] = b'\x7fELF\x02\x01'
    data[16:20] = b'\x03\x00\x3e\x00'
    return bytes(data) + payload


class EvidenceControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='stagea-evidence-control-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.raw, self.public = self.root / 'raw', self.root / 'public'
        self.raw.mkdir()
        self.public.mkdir()
        self.candidate = {'codex-rs/protocol/src/protocol.rs': 'unused-in-export-selector'}
        self.schema = {e.STABLE, 'codex-rs/app-server-protocol/schema/json/fixture.json'}
        self.result = {'completed': False, 'productQualified': False, 'failureCode': 'synthetic_primary_failure'}

    def put(self, name, data):
        path = self.raw / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return e.row_for(name, data)

    def put_json(self, name, value):
        return self.put(name, e.json_bytes(value))

    def read_json(self, name):
        return json.loads((self.raw / name).read_bytes())

    def binary_fixture(self, payload=b''):
        data = elf(payload)
        row = {**self.put('native-binaries/test-executable', data),
               'mode': '0o755', 'role': 'generator-test',
               'source': '<GENERATION_TARGET>/debug/deps/codex_app_server_protocol-012345abcdef'}
        value = {'files': [row], 'executableSha256': row['sha256'], 'productQualified': False}
        self.put_json('native-binaries.json', value)
        return value

    def full_fixture(self):
        binaries = self.binary_fixture(b'public library string\0-----BEGIN PRIVATE KEY-----\0')
        worker = {'completed': True, 'productQualified': False, 'phases': []}
        compressed = {}
        for label, (field, decoded_name) in e.DECODED.items():
            # Deliberately synthetic bytes: exporter checks the actual worker
            # decode receipt, while a separate runtime decoder creates it.
            compressed[label] = b'\x28\xb5\x2f\xfd synthetic fixture ' + label.encode()
            decoded = self.put_json(decoded_name, {'synthetic_control': label})
            worker[field] = {**decoded, 'compressedSha256': e.sha(compressed[label])}
            records = {}
            for name in self.schema:
                data = compressed[label] if name == e.STABLE else b'{"synthetic_control":true}\n'
                row = self.put(label + '/' + name, data)
                records[name] = {key: row[key] for key in ('bytes', 'sha256')}
            self.put_json(label + '.json', records)
        for label in e.LABELS:
            records = {}
            for name in self.candidate:
                row = self.put(label + '/' + name, b'// public synthetic source\n')
                records[name] = {key: row[key] for key in ('bytes', 'sha256')}
            if label in e.SOURCE_SCHEMA:
                row = self.put(label + '/' + e.STABLE, compressed[e.SOURCE_SCHEMA[label]])
                records[e.STABLE] = {key: row[key] for key in ('bytes', 'sha256')}
            self.put_json(label + '.json', records)
        for field, name in [('compileJUnit', 'compile-junit.xml'), ('generatorJUnit', 'generator-junit.xml')]:
            data = b'<testsuites><testsuite><testcase name="synthetic"/></testsuite></testsuites>\r\n'
            worker[field] = self.put(name, data)
        self.put('controller-junit.xml', (self.raw / 'generator-junit.xml').read_bytes())
        log = self.put('01-generator.log', b'public synthetic generator output\r\n')
        worker['phases'] = [{'phase': 'synthetic', 'log': log['path'], 'logBytes': log['bytes'], 'logSha256': log['sha256']}]
        worker['generatorBinary'] = {'files': binaries['files'], 'executableSha256': binaries['executableSha256'],
                                     'targetRelativePath': 'debug/deps/codex_app_server_protocol-012345abcdef'}
        self.put('generated-schema.patch', b'public synthetic schema patch\n')
        self.put_json('worker-result.json', worker)
        for name in e.JSON_NAMES:
            if not (self.raw / name).exists():
                self.put_json(name, {'synthetic_control': True})
        for name in e.PATCHES:
            if not (self.raw / name).exists():
                self.put(name, b'public synthetic patch\n')
        self.result = {'completed': True, 'productQualified': False, 'failureCode': None}
        return worker

    def export(self, **kwargs):
        e.export_audited(self.raw, self.public, self.result, self.candidate,
                         schema_files=self.schema, deadline=kwargs.pop('deadline', time.monotonic() + 30), **kwargs)
        return self.result

    def reasons(self):
        return {r['reason'] for r in self.result.get('evidenceAudit', {}).get('withheld', [])}

    def test_complete_synthetic_evidence_and_manifest_bytes(self):
        self.full_fixture()
        self.export()
        self.assertTrue(self.result['completed'], self.result)
        self.assertFalse(self.result['productQualified'])
        manifest = json.loads((self.public / 'evidence-manifest.json').read_bytes())
        names = set()
        for row in manifest['files']:
            self.assertNotIn(row['path'], names)
            names.add(row['path'])
            self.assertEqual(row, e.row_for(row['path'], (self.public / row['path']).read_bytes()))
        self.assertEqual(names, {str(p.relative_to(self.public)) for p in self.public.rglob('*') if p.is_file()} - {'evidence-manifest.json'})
        self.assertEqual((self.public / 'generator-junit.xml').read_bytes(), (self.raw / 'generator-junit.xml').read_bytes())
        ET.fromstring((self.public / 'normalized/generator-junit.xml.xml').read_bytes())

    def test_raw_and_normalized_logs_remain_separate(self):
        data = b'\x1b[31mpublic\x1b[0m\r\nentry\0'
        self.put('01-version.log', data)
        self.export()
        self.assertEqual((self.public / '01-version.log').read_bytes(), data)
        self.assertEqual((self.public / 'normalized/01-version.log.txt').read_bytes(), b'public\nentry\\0')
        self.assertFalse(self.result['completed'])
        self.assertEqual(self.result['failureCode'], 'synthetic_primary_failure')

    def test_missing_required_completed_bytes_cannot_pass(self):
        self.full_fixture()
        (self.raw / 'generator-junit.xml').unlink()
        self.export()
        self.assertFalse(self.result['completed'])
        self.assertIn('completed_run_required_evidence_missing', self.reasons())

    def test_completed_controller_without_worker_is_incomplete(self):
        self.result['completed'] = True
        self.export()
        self.assertFalse(self.result['completed'])
        self.assertIn('completed_run_binding_missing', self.reasons())

    def test_completed_run_retains_prerequisite_receipts_too(self):
        self.full_fixture()
        (self.raw / 'closure.json').unlink()
        self.export()
        self.assertFalse(self.result['completed'])
        self.assertIn('completed_run_required_evidence_missing', self.reasons())

    def test_missing_phase_log_binding_is_not_aggregate_success(self):
        worker = self.full_fixture()
        worker['phases'][0]['logSha256'] = 'f' * 64
        self.put_json('worker-result.json', worker)
        self.export()
        self.assertIn('completed_phase_log_binding_missing', self.reasons())

    def test_junit_worker_hash_must_match(self):
        worker = self.full_fixture()
        worker['generatorJUnit']['sha256'] = 'f' * 64
        self.put_json('worker-result.json', worker)
        self.export()
        self.assertIn('completed_junit_binding_missing', self.reasons())

    def test_text_private_key_header_is_still_forbidden(self):
        data = b'library header -----BEGIN PRIVATE KEY-----'
        self.put('01-tool.log', data)
        self.export()
        self.assertFalse((self.public / '01-tool.log').exists())
        self.assertEqual(self.result['evidenceAudit']['withheld'][0]['sha256'], e.sha(data))

    def test_binary_header_only_library_string_is_permitted(self):
        self.binary_fixture(b'-----BEGIN RSA PRIVATE KEY-----\0unrelated string')
        self.export()
        self.assertTrue((self.public / 'native-binaries/test-executable').exists())

    def test_binary_complete_synthetic_pem_is_withheld_across_chunks(self):
        payload = b'\0' * 53 + b'-----BEGIN PRIVATE KEY-----\n' + b'QUJDREVGR0hJSktMTU5PUA==\n' * 5 + b'-----END PRIVATE KEY-----\0'
        self.binary_fixture(payload)
        with patch.object(e, 'CHUNK', 64):
            self.export()
        self.assertIn('binary_privacy_audit_hold', self.reasons())
        self.assertFalse((self.public / 'native-binaries/test-executable').exists())
        self.assertFalse(list(self.public.rglob('*.auditing')))

    def test_binary_token_is_withheld_across_chunks(self):
        self.binary_fixture(b'\0' * 59 + b'ghp_' + b'SYNTHETIC' * 4 + b'\0')
        with patch.object(e, 'CHUNK', 64):
            self.export()
        self.assertIn('binary_privacy_audit_hold', self.reasons())

    def test_binary_unbounded_pending_pem_is_conservatively_held(self):
        self.assertFalse(e.binary_window_safe(b'-----BEGIN PRIVATE KEY-----' + b'A' * 32768))

    def test_binary_unlisted_even_when_elf(self):
        self.put('native-binaries/unknown', elf())
        self.export()
        self.assertIn('unlisted_binary', self.reasons())
        self.assertFalse((self.public / 'native-binaries/unknown').exists())

    def test_binary_not_elf_with_correct_hash_is_withheld(self):
        manifest = self.binary_fixture()
        data = b'not-ELF' * 10
        row = self.put('native-binaries/test-executable', data)
        manifest['files'][0].update(row)
        manifest['executableSha256'] = row['sha256']
        self.put_json('native-binaries.json', manifest)
        self.export()
        self.assertIn('binary_not_x86_64_elf', self.reasons())

    def test_binary_hash_mismatch_does_not_publish_partial_copy(self):
        manifest = self.binary_fixture()
        manifest['files'][0]['sha256'] = manifest['executableSha256'] = '0' * 64
        self.put_json('native-binaries.json', manifest)
        self.export()
        self.assertIn('binary_hash_mismatch', self.reasons())
        self.assertFalse(list((self.public / 'native-binaries').iterdir()))

    def test_binary_size_mismatch_is_withheld(self):
        manifest = self.binary_fixture()
        manifest['files'][0]['bytes'] += 1
        self.put_json('native-binaries.json', manifest)
        self.export()
        self.assertIn('binary_size_or_type', self.reasons())

    def test_binary_manifest_duplicate_wrong_role_and_provenance_reject(self):
        manifest = self.binary_fixture()
        cases = []
        duplicate = copy.deepcopy(manifest)
        duplicate['files'].append(duplicate['files'][0].copy())
        cases.append(duplicate)
        for key, value in [('role', 'arbitrary'), ('source', '/tmp/arbitrary'), ('path', 'native-binaries/../escape')]:
            bad = copy.deepcopy(manifest)
            bad['files'][0][key] = value
            cases.append(bad)
        for bad in cases:
            with self.subTest(bad=bad), self.assertRaises(RuntimeError):
                e.binary_records(bad)

    def test_binary_aggregate_budget_separate_from_text(self):
        manifest = self.binary_fixture()
        runtime = {**manifest['files'][0], 'path': 'native-binaries/runtime-libfixture.so',
                   'role': 'system-runtime', 'source': '/usr/lib/x86_64-linux-gnu/libfixture.so'}
        manifest['files'].append(runtime)
        with patch.object(e, 'MAX_BINARY_BYTES', 100), self.assertRaisesRegex(RuntimeError, 'binary_aggregate_bound'):
            e.binary_records(manifest)
        self.export()
        self.assertEqual(self.result['evidenceAudit']['binaryBytes'], 64)

    def test_binary_deadline_removes_only_its_partial_file(self):
        manifest = self.binary_fixture(b'public data' * 20)
        checks = iter([None, None, RuntimeError('export_deadline')])
        def bounded(_):
            value = next(checks, RuntimeError('export_deadline'))
            if value:
                raise value
        with patch.object(e, 'CHUNK', 64), patch.object(e, 'check_time', side_effect=bounded), self.assertRaisesRegex(RuntimeError, 'export_deadline'):
            e.copy_binary(self.raw, self.public, manifest['files'][0], time.monotonic() + 20)
        self.assertFalse(list(self.public.rglob('*.auditing')))
        self.assertTrue((self.raw / 'native-binaries/test-executable').exists())

    def test_binary_symlink_target_is_not_read(self):
        manifest = self.binary_fixture()
        path = self.raw / 'native-binaries/test-executable'
        path.unlink()
        path.symlink_to(self.root / 'absent-target')
        self.export()
        self.assertIn('nonregular_entry', self.reasons())
        self.assertTrue(path.is_symlink())

    def test_schema_missing_decode_withholds_compressed_bytes(self):
        worker = self.full_fixture()
        del worker['decodedGenerated']
        self.put_json('worker-result.json', worker)
        self.export()
        self.assertIn('decoded_schema_binding', self.reasons())
        self.assertFalse((self.public / 'schema-generated' / e.STABLE).exists())

    def test_schema_decode_secret_withholds_archive_and_plaintext(self):
        worker = self.full_fixture()
        name = 'generated-stable-decoded.json'
        row = self.put_json(name, {'token': 'ghp_' + 'SYNTHETIC' * 4})
        worker['decodedGenerated'].update(row)
        self.put_json('worker-result.json', worker)
        self.export()
        self.assertFalse((self.public / name).exists())
        self.assertFalse((self.public / 'schema-generated' / e.STABLE).exists())

    def test_schema_decode_receipt_hash_mismatch_withholds_archive(self):
        worker = self.full_fixture()
        worker['decodedBefore']['sha256'] = 'f' * 64
        self.put_json('worker-result.json', worker)
        self.export()
        self.assertIn('decoded_schema_hash', self.reasons())
        self.assertFalse((self.public / 'base-source' / e.STABLE).exists())

    def test_json_escaped_token_is_audited_after_decoding(self):
        worker = self.full_fixture()
        name = 'generated-stable-decoded.json'
        data = b'{"value":"\\u0067hp_' + b'SYNTHETIC' * 4 + b'"}'
        worker['decodedGenerated'].update(self.put(name, data))
        self.put_json('worker-result.json', worker)
        self.export()
        self.assertIn('decoded_json_privacy_hold', self.reasons())
        self.assertFalse((self.public / name).exists())
        self.assertFalse((self.public / 'schema-generated' / e.STABLE).exists())

    def test_elf_cannot_be_disguised_as_allowed_log(self):
        self.put('01-tool.log', elf(b'public bytes'))
        self.export()
        self.assertIn('binary_in_text_route', self.reasons())
        self.assertFalse((self.public / '01-tool.log').exists())

    def test_schema_compressed_hash_is_exact(self):
        self.full_fixture()
        path = self.raw / 'schema-generated' / e.STABLE
        path.write_bytes(path.read_bytes() + b'changed')
        self.export()
        self.assertIn('compressed_schema_hash', self.reasons())

    def test_schema_non_zstd_bytes_not_a_binary_bypass(self):
        self.full_fixture()
        (self.raw / 'schema-generated' / e.STABLE).write_bytes(b'not compressed')
        self.export()
        self.assertIn('compressed_schema_not_zstd', self.reasons())

    def test_schema_unlisted_path_and_source_expansion_rejected(self):
        self.assertFalse(e.allowed('schema-final/not-pinned.json', self.candidate, self.schema))
        self.assertFalse(e.allowed('formatted-source/codex-rs/app-server-protocol/schema/json/fixture.json', self.candidate, self.schema))
        self.assertFalse(e.allowed('candidate-source/' + e.STABLE, self.candidate, self.schema))
        self.assertTrue(e.allowed('schema-final/' + e.STABLE, self.candidate, self.schema))

    def test_schema_manifest_extra_path_is_rejected(self):
        self.full_fixture()
        value = self.read_json('schema-generated.json')
        value['unlisted'] = {'bytes': 0, 'sha256': e.sha(b'')}
        self.put_json('schema-generated.json', value)
        self.export()
        self.assertIn('schema_manifest_inventory', self.reasons())

    def test_selected_snapshot_hash_is_checked(self):
        self.full_fixture()
        self.put('formatted-source/' + next(iter(self.candidate)), b'changed')
        self.export()
        self.assertIn('selected_snapshot_hash', self.reasons())

    def test_xml_normalization_escapes_text_and_attributes(self):
        data = b'<testsuite><testcase name="&lt;SUBJECT&gt;"><failure>path &lt;SUBJECT&gt;</failure></testcase></testsuite>'
        self.put('controller-junit.xml', data)
        self.export()
        self.assertEqual((self.public / 'controller-junit.xml').read_bytes(), data)
        root = ET.fromstring((self.public / 'normalized/controller-junit.xml.xml').read_bytes())
        self.assertEqual(root.find('testcase').attrib['name'], '<SUBJECT>')

    def test_xml_entity_or_doctype_is_rejected(self):
        self.put('generator-junit.xml', b'<!DOCTYPE x [<!ENTITY a "value">]><x>&a;</x>')
        self.export()
        self.assertIn('xml_declaration_forbidden', self.reasons())
        self.assertFalse((self.public / 'generator-junit.xml').exists())

    def test_normalized_secret_cannot_escape_raw_audit(self):
        self.put('01-tool.log', b'GH_\x1b[0mTOKEN=synthetic-sensitive-value\n')
        self.put('generator-junit.xml', b'<x>GH_&#84;OKEN=synthetic-sensitive-value</x>')
        self.export()
        self.assertIn('normalized_privacy_audit_hold', self.reasons())
        self.assertFalse((self.public / '01-tool.log').exists())

    def test_deadline_keeps_small_truthful_receipt(self):
        self.put('01-tool.log', b'public')
        self.export(deadline=time.monotonic() - 1)
        self.assertIn('export_deadline', self.reasons())
        self.assertFalse(self.result['completed'])
        self.assertTrue((self.public / 'controller-result.json').is_file())

    def test_text_and_aggregate_limits(self):
        self.put('worker-progress.json', b'x' * 41)
        self.put('01-tool.log', b'x' * 11)
        with patch.object(e, 'TEXT_LIMIT', 40), patch.object(e, 'MAX_EVIDENCE_BYTES', e.METADATA_RESERVE + 20):
            self.export()
        self.assertIn('file_size_bound', self.reasons())
        self.assertIn('evidence_size_bound', self.reasons())

    def test_public_receipt_does_not_echo_private_controller_message(self):
        self.result['message'] = '/Users/SYNTHETIC/Documents/private'
        self.export()
        data = (self.public / 'controller-result.json').read_bytes()
        self.assertNotIn(b'/Users/', data)
        self.assertEqual(self.result['evidenceFailure'], 'final_receipt_privacy_or_size_hold')

    def test_directory_symlink_and_unknown_file_are_not_followed(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / '01-tool.log').write_text('public sentinel')
        (self.raw / 'foreign').symlink_to(outside, target_is_directory=True)
        self.put('unknown.bin', b'public sentinel')
        self.export()
        self.assertIn('nonregular_entry', self.reasons())
        self.assertIn('unlisted_entry', self.reasons())
        self.assertFalse((self.public / 'foreign').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
