#!/usr/bin/env python3
"""Bounded StageA evidence export. Raw bytes remain authoritative."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import xml.etree.ElementTree as ET

from controller import MAX_BINARY_BYTES, MAX_EVIDENCE_BYTES, need, safe_path

MIB = 1024**2
TEXT_LIMIT, LOG_LIMIT, XML_LIMIT = 32 * MIB, 64 * MIB, 8 * MIB
METADATA_RESERVE, CHUNK, SCAN_TAIL, MAX_ENTRIES = 2 * MIB, MIB, 128 * 1024, 15000
STABLE = 'codex-rs/app-server-protocol/schema/precomputed/app-server-exports-stable.json.zst'
JSON_NAMES = {
    'worker-result.json', 'worker-progress.json', 'download-receipts.json',
    'tool-identity.json', 'source-layout.json', 'base-tree.json',
    'pre-format-tree.json', 'compile-tree.json', 'post-format-tree.json', 'final-tree.json',
    'metadata-target.json', 'source-delta.json', 'controller-final-tree.json',
    'native-binaries.json', 'cargo-lock-provenance.json', 'cargo-cache-inventory.json',
    'closure.json', 'resource-admission.json', 'schema-before.json',
    'schema-generated.json', 'schema-final.json', 'generation-tree.json',
    'generation-delta.json', 'metadata-before-compile.json',
    'native-target-inventory.json', 'baseline-stable-decoded.json',
    'generated-stable-decoded.json', 'final-stable-decoded.json',
}
LABELS = {'base-source', 'candidate-source', 'formatted-source', 'final-source', 'controller-final'}
SCHEMA_LABELS = {'schema-before', 'schema-generated', 'schema-final'}
PATCHES = {'candidate.patch', 'formatted.patch', 'formatter-delta.patch', 'generated-schema.patch'}
XML_NAMES = {'generator-junit.xml', 'compile-junit.xml', 'controller-junit.xml'}
DECODED = {
    'schema-before': ('decodedBefore', 'baseline-stable-decoded.json'),
    'schema-generated': ('decodedGenerated', 'generated-stable-decoded.json'),
    'schema-final': ('decodedFinal', 'final-stable-decoded.json'),
}
SOURCE_SCHEMA = {'base-source': 'schema-before', 'formatted-source': 'schema-final',
                 'final-source': 'schema-final', 'controller-final': 'schema-final'}
SECRET_PATTERNS = [
    rb'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----',
    rb'\b(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}', rb'\bAKIA[A-Z0-9]{16}\b',
    rb'(?i)\bBearer[ \t]+[A-Za-z0-9._-]{24,}',
    rb'(?m)^(?:GH_TOKEN|GITHUB_TOKEN|ACTIONS_RUNTIME_TOKEN|AWS_SECRET_ACCESS_KEY)=[^\s]+',
    rb'/Users/[^/\s]+/(?:Documents|\.ssh|\.aws)/', rb'/private/var/folders/',
]
PEM_COMPLETE = re.compile(rb'-----BEGIN ((?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----([A-Za-z0-9+/=\r\n\t ]{16,}?)-----END \1-----')
# Stop conservatively if a potential credential could exceed the stream window.
# A header alone is permitted only in ELF, never in text.
BINARY_SPAN = re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[A-Za-z0-9+/=\r\n\t ]{32768}|/Users/[^/\s]{32768}|(?i:Bearer)[ \t]{32768}')


def allowed(name, candidate_files, schema_files=()):
    p = Path(name)
    if p.is_absolute() or '..' in p.parts or str(p) != name:
        return False
    if len(p.parts) == 1:
        return (name in JSON_NAMES | PATCHES | XML_NAMES or name == 'controller-raw.log'
                or bool(re.fullmatch(r'[0-9]{2,3}-[a-z0-9-]+\.log', name))
                or name in {x + '.json' for x in LABELS})
    label, relative = p.parts[0], str(Path(*p.parts[1:]))
    if label in SCHEMA_LABELS:
        return relative in schema_files
    if label in LABELS:
        return relative in candidate_files or (label != 'candidate-source' and relative == STABLE and STABLE in schema_files)
    return False


def audit_bytes(data):
    return not any(re.search(pattern, data) for pattern in SECRET_PATTERNS)


def normalized(data):
    text = data.decode('utf-8', errors='backslashreplace').replace('\r\n', '\n').replace('\x00', '\\0')
    return re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text).encode('utf-8')


def normalized_xml(data):
    need(not re.search(rb'<!\s*(?:DOCTYPE|ENTITY)', data, re.I), 'xml_declaration_forbidden')
    root = ET.fromstring(data)
    for element in root.iter():
        for key, value in list(element.attrib.items()):
            need(audit_bytes(key.encode()) and audit_bytes(value.encode()), 'xml_decoded_privacy_hold')
            element.set(key, normalized(value.encode()).decode())
        if element.text is not None:
            need(audit_bytes(element.text.encode()), 'xml_decoded_privacy_hold')
            element.text = normalized(element.text.encode()).decode()
        if element.tail is not None:
            need(audit_bytes(element.tail.encode()), 'xml_decoded_privacy_hold')
            element.tail = normalized(element.tail.encode()).decode()
    return ET.tostring(root, encoding='utf-8', xml_declaration=True)


def check_time(deadline):
    need(time.monotonic() < deadline, 'export_deadline')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def row_for(name, data):
    return {'path': name, 'bytes': len(data), 'sha256': sha(data)}


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def text_bytes(data):
    need(not data.startswith((b'\x7fELF', b'MZ', b'\x28\xb5\x2f\xfd')), 'binary_in_text_route')
    data.decode('utf-8')


def audit_json_strings(value, deadline):
    pending, count = [value], 0
    while pending:
        check_time(deadline)
        item = pending.pop()
        count += 1
        need(count <= 500000, 'json_audit_entry_bound')
        if isinstance(item, str):
            need(audit_bytes(item.encode()), 'decoded_json_privacy_hold')
        elif isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)


def checked_read(raw, name, limit, deadline):
    check_time(deadline)
    fd = os.open(safe_path(raw, name), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode), 'nonregular_entry')
        need(before.st_size <= limit, 'file_size_bound')
        data = bytearray()
        while True:
            check_time(deadline)
            block = os.read(fd, min(CHUNK, limit + 1 - len(data)))
            if not block:
                break
            data.extend(block)
            need(len(data) <= limit, 'file_size_bound')
        after = os.fstat(fd)
        need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
             == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
             and len(data) == before.st_size, 'file_changed_during_export')
        return bytes(data)
    finally:
        os.close(fd)


def binary_window_safe(data):
    if any(re.search(pattern, data) for pattern in SECRET_PATTERNS[1:]) or BINARY_SPAN.search(data):
        return False
    return not any(len(re.sub(rb'\s', b'', match.group(2))) >= 16 for match in PEM_COMPLETE.finditer(data))


def copy_binary(raw, public, row, deadline):
    """Stream into an unpublished temporary file; rename only after full audit."""
    name = row['path']
    source = safe_path(raw, name)
    destination = public / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    need(stat.S_ISDIR(destination.parent.lstat().st_mode), 'binary_destination_parent')
    temporary = destination.with_name(destination.name + '.auditing')
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    made = False
    try:
        original = os.fstat(fd)
        need(stat.S_ISREG(original.st_mode) and original.st_size == row['bytes'], 'binary_size_or_type')
        need(not destination.exists() and not destination.is_symlink(), 'export_destination_exists')
        with temporary.open('xb') as output:
            made = True
            h, total, tail = hashlib.sha256(), 0, b''
            while True:
                check_time(deadline)
                block = os.read(fd, CHUNK)
                if not block:
                    break
                if total == 0:
                    need(len(block) >= 20 and block[:6] == b'\x7fELF\x02\x01'
                         and int.from_bytes(block[16:18], 'little') in (2, 3)
                         and int.from_bytes(block[18:20], 'little') == 62, 'binary_not_x86_64_elf')
                total += len(block)
                need(total <= row['bytes'], 'binary_changed_during_export')
                window = tail + block
                need(binary_window_safe(window), 'binary_privacy_audit_hold')
                tail = window[-SCAN_TAIL:]
                h.update(block)
                output.write(block)
            current = os.fstat(fd)
            need(total == row['bytes'] and h.hexdigest() == row['sha256'], 'binary_hash_mismatch')
            need((original.st_dev, original.st_ino, original.st_size, original.st_mtime_ns)
                 == (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns), 'binary_changed_during_export')
        check_time(deadline)
        temporary.rename(destination)
        made = False
        return {key: row[key] for key in ('path', 'bytes', 'sha256', 'mode', 'role', 'source')}
    finally:
        os.close(fd)
        if made:
            temporary.unlink()


def binary_records(value):
    rows = value.get('files')
    need(isinstance(rows, list) and 1 <= len(rows) <= 33, 'binary_manifest_shape')
    names, total, executables = set(), 0, []
    for row in rows:
        need(isinstance(row, dict) and set(row) == {'path', 'bytes', 'sha256', 'mode', 'role', 'source'}, 'binary_manifest_fields')
        name, role, source = row['path'], row['role'], row['source']
        need(isinstance(name, str) and re.fullmatch(r'native-binaries/(?:test-executable|runtime-[A-Za-z0-9._+-]+)', name) is not None
             and name not in names, 'binary_manifest_path')
        names.add(name)
        need(type(row['bytes']) is int and 20 <= row['bytes'] <= MAX_BINARY_BYTES
             and isinstance(row['sha256'], str) and re.fullmatch('[a-f0-9]{64}', row['sha256']), 'binary_manifest_identity')
        need(isinstance(source, str), 'binary_manifest_provenance')
        need(isinstance(row['mode'], str) and re.fullmatch(r'0o[0-7]{3}', row['mode']), 'binary_source_mode')
        if role == 'generator-test':
            need(name == 'native-binaries/test-executable' and re.fullmatch(r'<GENERATION_TARGET>/debug/deps/codex_app_server_protocol-[a-f0-9]+', source), 'binary_executable_provenance')
            need(int(row['mode'], 8) & 0o111, 'binary_source_not_executable')
            executables.append(row)
        else:
            need(role in {'system-runtime', 'system-interpreter'}
                 and re.fullmatch(r'/(?:usr/)?lib/x86_64-linux-gnu/[A-Za-z0-9._+-]+', source)
                 and name == 'native-binaries/runtime-' + Path(source).name, 'binary_runtime_provenance')
        total += row['bytes']
    need(total <= MAX_BINARY_BYTES, 'binary_aggregate_bound')
    need(len(executables) == 1 and value.get('executableSha256') == executables[0]['sha256']
         and value.get('productQualified') is False, 'binary_executable_binding')
    return {row['path']: row for row in rows}


def export_audited(raw, public, result, candidate_files, *, schema_files=(), deadline=None):
    # Old synthetic callers receive a bounded default; the controller supplies
    # its absolute global deadline, including its cleanup/export reserve.
    if deadline is None:
        deadline = time.monotonic() + 120
    exported, withheld, manifest_rows, published = [], [], [], set()
    total, binary_total = 0, 0
    cached, values, invalid = {}, {}, set()
    worker, binaries = {}, {}
    schema_files = set(schema_files)

    def hold(name, reason, data=None):
        if name in invalid:
            return
        invalid.add(name)
        safe_name = name if audit_bytes(name.encode()) else '<withheld-path-sha256:' + sha(name.encode()) + '>'
        row = {'path': safe_name, 'reason': reason}
        if data is not None:
            row.update(bytes=len(data), sha256=sha(data))
        withheld.append(row)

    def load_json(name):
        if name in values:
            return values[name]
        need(name not in invalid, 'required_json_unavailable')
        data = checked_read(raw, name, TEXT_LIMIT, deadline)
        text_bytes(data)
        if not audit_bytes(data):
            hold(name, 'privacy_audit_hold', data)
            raise RuntimeError('required_json_privacy_hold')
        value = json.loads(data)
        need(isinstance(value, dict), 'json_object_required')
        audit_json_strings(value, deadline)
        cached[name], values[name] = data, value
        return value

    def schema_binding(label, data):
        schema_label = SOURCE_SCHEMA.get(label, label)
        need(schema_label in DECODED and STABLE in schema_files, 'compressed_schema_path')
        need(data[:4] == b'\x28\xb5\x2f\xfd', 'compressed_schema_not_zstd')
        schema = load_json(schema_label + '.json')
        need(set(schema) == schema_files, 'schema_manifest_inventory')
        need(schema.get(STABLE) == {'bytes': len(data), 'sha256': sha(data)}, 'compressed_schema_hash')
        field, decoded_name = DECODED[schema_label]
        receipt = worker.get(field, {})
        need(isinstance(receipt, dict) and receipt.get('path') == decoded_name
             and receipt.get('compressedSha256') == sha(data), 'decoded_schema_binding')
        load_json(decoded_name)
        decoded_data = cached[decoded_name]
        need(receipt.get('bytes') == len(decoded_data) and receipt.get('sha256') == sha(decoded_data), 'decoded_schema_hash')
        need(decoded_name in published and schema_label + '.json' in published, 'decoded_schema_not_retained')
        # The worker's actual zstd decode receipt supplies this byte binding.
        # Semantic equality and intended source/schema deltas remain root checks.

    try:
        need(stat.S_ISDIR(raw.lstat().st_mode) and stat.S_ISDIR(public.lstat().st_mode), 'export_root_type')
        need(not any(public.iterdir()), 'export_destination_not_empty')
        if (raw / 'worker-result.json').exists():
            try:
                worker = load_json('worker-result.json')
            except Exception as error:
                hold('worker-result.json', error_code(error))
        if (raw / 'native-binaries.json').exists():
            try:
                binaries = binary_records(load_json('native-binaries.json'))
            except Exception as error:
                hold('native-binaries.json', error_code(error))
        pending, entries, paths = [raw], 0, []
        while pending:
            check_time(deadline)
            directory = pending.pop()
            for path in directory.iterdir():
                check_time(deadline)
                entries += 1
                need(entries <= MAX_ENTRIES, 'export_entry_bound')
                if stat.S_ISDIR(path.lstat().st_mode):
                    pending.append(path)
                else:
                    paths.append(path)
        # Receipts precede ELF copies and compressed schema bytes. No symlink
        # target is traversed or opened during inventory or export.
        for path in sorted(paths, key=lambda p: (p.suffix == '.zst', 'native-binaries' in p.parts, str(p))):
            name = str(path.relative_to(raw))
            if name in invalid:
                continue
            try:
                check_time(deadline)
                need(stat.S_ISREG(path.lstat().st_mode), 'nonregular_entry')
                need(audit_bytes(name.encode()), 'pathname_privacy_hold')
                if name.startswith('native-binaries/'):
                    need(name in binaries and 'native-binaries.json' in published, 'unlisted_binary')
                    need(binary_total + binaries[name]['bytes'] <= MAX_BINARY_BYTES, 'binary_aggregate_bound')
                    record = copy_binary(raw, public, binaries[name], deadline)
                    binary_total += record['bytes']
                    exported.append(record)
                    manifest_rows.append({k: record[k] for k in ('path', 'bytes', 'sha256')})
                    published.add(name)
                    continue
                need(allowed(name, candidate_files, schema_files), 'unlisted_entry')
                limit = LOG_LIMIT if path.suffix == '.log' else XML_LIMIT if name in XML_NAMES else TEXT_LIMIT
                data = cached.get(name)
                if data is None:
                    data = checked_read(raw, name, limit, deadline)
                if path.suffix == '.zst':
                    need(str(Path(*Path(name).parts[1:])) == STABLE, 'unlisted_compressed_entry')
                    schema_binding(Path(name).parts[0], data)
                else:
                    text_bytes(data)
                    if not audit_bytes(data):
                        hold(name, 'privacy_audit_hold', data)
                        continue
                    if name.endswith('.json'):
                        audit_json_strings(json.loads(data), deadline)
                if name.startswith(tuple(label + '/' for label in SCHEMA_LABELS)):
                    label, relative = name.split('/', 1)
                    schema = load_json(label + '.json')
                    need(set(schema) == schema_files and schema.get(relative) == {'bytes': len(data), 'sha256': sha(data)}, 'schema_snapshot_hash')
                if name.startswith(tuple(label + '/' for label in LABELS)):
                    label, relative = name.split('/', 1)
                    selected = load_json(label + '.json')
                    expected = set(candidate_files) | ({STABLE} if label != 'candidate-source' and STABLE in schema_files else set())
                    need(set(selected) == expected and selected.get(relative) == {'bytes': len(data), 'sha256': sha(data)}, 'selected_snapshot_hash')
                transformed = normalized(data) if path.suffix == '.log' else normalized_xml(data) if name in XML_NAMES else None
                need(transformed is None or audit_bytes(transformed), 'normalized_privacy_audit_hold')
                addition = len(data) + (len(transformed) if transformed is not None else 0)
                need(total + addition <= MAX_EVIDENCE_BYTES - METADATA_RESERVE, 'evidence_size_bound')
                check_time(deadline)
                destination = public / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open('xb') as output:
                    output.write(data)
                total += addition
                record = row_for(name, data)
                manifest_rows.append(record.copy())
                published.add(name)
                if transformed is not None:
                    normalized_name = 'normalized/' + name + ('.xml' if name in XML_NAMES else '.txt')
                    copy = public / normalized_name
                    copy.parent.mkdir(parents=True, exist_ok=True)
                    with copy.open('xb') as output:
                        output.write(transformed)
                    record['normalized'] = row_for(normalized_name, transformed)
                    manifest_rows.append(record['normalized'].copy())
                exported.append(record)
            except Exception as error:
                hold(name, error_code(error))
                if isinstance(error, RuntimeError) and str(error) == 'export_deadline':
                    break
        if worker.get('completed') is True or result.get('completed') is True:
            required = JSON_NAMES | PATCHES | {'generator-junit.xml', 'compile-junit.xml'}
            required.update(label + '.json' for label in LABELS)
            required.update(name for _, name in DECODED.values())
            required.update(binaries)
            required.update(label + '/' + name for label in SCHEMA_LABELS for name in schema_files)
            required.update(label + '/' + name for label in LABELS for name in candidate_files)
            required.update(label + '/' + STABLE for label in SOURCE_SCHEMA)
            for name in sorted(required - published):
                hold(name, 'completed_run_required_evidence_missing')
            if not binaries or not schema_files or worker.get('completed') is not True:
                hold('<completion>', 'completed_run_binding_missing')
            for field in ('compileJUnit', 'generatorJUnit'):
                receipt = worker.get(field, {})
                records = [r for r in manifest_rows if r['path'] == receipt.get('path')]
                if len(records) != 1 or records[0] != receipt:
                    hold('<' + field + '>', 'completed_junit_binding_missing')
            binary_receipt = worker.get('generatorBinary', {})
            if binary_receipt.get('files') != list(binaries.values()) or binary_receipt.get('executableSha256') != values.get('native-binaries.json', {}).get('executableSha256'):
                hold('<generatorBinary>', 'completed_binary_binding_missing')
            phases = worker.get('phases', [])
            if not phases:
                hold('<phases>', 'completed_phase_logs_missing')
            for phase in phases:
                record = {'path': phase.get('log'), 'bytes': phase.get('logBytes'), 'sha256': phase.get('logSha256')}
                if record not in manifest_rows:
                    hold('<phase-log>', 'completed_phase_log_binding_missing')
    except Exception as error:
        hold('<export>', error_code(error))
    if withheld:
        result['completed'] = False
        result['evidenceFailure'] = 'withheld_or_incomplete_evidence'
    result['productQualified'] = False
    result['evidenceAudit'] = {
        'exportedFiles': len(exported), 'exportedBytes': total + binary_total,
        'textAndSchemaBytes': total, 'binaryBytes': binary_total, 'withheld': withheld,
        'rawRetention': 'Exact selected audited raw bytes are durable in uploaded artifact. Withheld raw remains only on ephemeral runner; no durable retention or reconstruction is claimed for withheld data.',
        'compressedSchemaAudit': 'Exact manifest hash and corresponding audited decoded JSON receipt; semantic review remains pending.',
    }
    audit_data, result_data = json_bytes({'files': exported, 'withheld': withheld}), json_bytes(result)
    # Small final receipts are written even after deadline; no unexpected
    # private exception/message is copied into the public failure receipt.
    if not audit_bytes(audit_data) or not audit_bytes(result_data) or len(audit_data) + len(result_data) > METADATA_RESERVE // 2:
        result.clear()
        result.update(completed=False, productQualified=False, evidenceFailure='final_receipt_privacy_or_size_hold')
        audit_data = json_bytes({'withheld': [{'path': '<metadata>', 'reason': 'final_receipt_privacy_or_size_hold'}]})
        result_data = json_bytes(result)
    for name, data in [('export-audit.json', audit_data), ('controller-result.json', result_data)]:
        (public / name).write_bytes(data)
        manifest_rows.append(row_for(name, data))
    manifest_data = json_bytes({'files': sorted(manifest_rows, key=lambda row: row['path'])})
    need(len(manifest_data) + len(audit_data) + len(result_data) <= METADATA_RESERVE, 'final_manifest_size_bound')
    (public / 'evidence-manifest.json').write_bytes(manifest_data)


def error_code(error):
    value = str(error)
    return value if isinstance(error, RuntimeError) and re.fullmatch('[a-z0-9_]+', value) else type(error).__name__
