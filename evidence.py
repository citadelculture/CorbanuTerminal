#!/usr/bin/env python3
"""Fixed, audited format-only evidence export; raw bytes remain authoritative."""
import hashlib
import re
import shutil
import stat
from pathlib import Path
from controller import MAX_EVIDENCE_BYTES, digest, need, safe_path, write

JSON_NAMES = {'worker-result.json', 'worker-progress.json', 'download-receipts.json', 'tool-identity.json', 'source-layout.json', 'base-tree.json', 'pre-format-tree.json', 'post-format-tree.json', 'final-tree.json', 'metadata-target.json', 'source-delta.json', 'controller-final-tree.json'}
LABELS = {'base-source', 'candidate-source', 'formatted-source', 'final-source', 'controller-final'}
PATCHES = {'candidate.patch', 'formatted.patch', 'formatter-delta.patch'}
SECRET_PATTERNS = [rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', rb'\b(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}', rb'\bAKIA[A-Z0-9]{16}\b', rb'(?i)\bBearer[ \t]+[A-Za-z0-9._-]{24,}', rb'(?m)^(?:GH_TOKEN|GITHUB_TOKEN|ACTIONS_RUNTIME_TOKEN|AWS_SECRET_ACCESS_KEY)=[^\s]+', rb'/Users/[^/\s]+/(?:Documents|\.ssh|\.aws)/', rb'/private/var/folders/']


def allowed(name, candidate_files):
    p = Path(name)
    if len(p.parts) == 1:
        return name in JSON_NAMES or name in PATCHES or name == 'controller-raw.log' or bool(re.fullmatch(r'[0-9]{2,3}-[a-z0-9-]+\.log', name)) or name in {x + '.json' for x in LABELS}
    return p.parts[0] in LABELS and str(Path(*p.parts[1:])) in candidate_files


def audit_bytes(data):
    return not any(re.search(pattern, data) for pattern in SECRET_PATTERNS)


def normalized(data):
    text = data.decode('utf-8', errors='backslashreplace').replace('\r\n', '\n').replace('\x00', '\\0')
    return re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text).encode('utf-8')


def export_audited(raw, public, result, candidate_files):
    exported, withheld = [], []
    total = 0
    for path in sorted(raw.rglob('*')):
        name = str(path.relative_to(raw))
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        reason = None
        if not stat.S_ISREG(mode):
            reason = 'nonregular_entry'
        elif not allowed(name, candidate_files):
            reason = 'unlisted_entry'
        elif path.stat().st_size > 64 * 1024**2:
            reason = 'file_size_bound'
        if reason:
            withheld.append({'path': name, 'reason': reason})
            continue
        # Safe parent walk precedes every open, including malicious child entries.
        try:
            checked = safe_path(raw, name)
            data = checked.read_bytes()
        except BaseException as error:
            withheld.append({'path': name, 'reason': 'read_' + type(error).__name__})
            continue
        if not audit_bytes(data):
            withheld.append({'path': name, 'reason': 'privacy_audit_hold', 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
            continue
        normalized_data = normalized(data) if path.suffix == '.log' else None
        addition = len(data) + (len(normalized_data) if normalized_data is not None else 0)
        if total + addition > MAX_EVIDENCE_BYTES - 2 * 1024**2:
            withheld.append({'path': name, 'reason': 'evidence_size_bound', 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
            continue
        total += addition
        destination = public / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        record = {'path': name, 'bytes': len(data), 'sha256': digest(destination)}
        if path.suffix == '.log':
            copy = public / 'normalized' / (name + '.txt')
            copy.parent.mkdir(parents=True, exist_ok=True)
            copy.write_bytes(normalized_data)
            record['normalized'] = {'path': str(copy.relative_to(public)), 'bytes': copy.stat().st_size, 'sha256': digest(copy)}
        exported.append(record)
    total = sum(p.stat().st_size for p in public.rglob('*') if p.is_file())
    if total > MAX_EVIDENCE_BYTES:
        withheld.append({'path': '<aggregate>', 'reason': 'evidence_size_bound'})
    if withheld:
        result['completed'] = False
        result['evidenceFailure'] = 'withheld_or_incomplete_evidence'
    result['evidenceAudit'] = {'exportedFiles': len(exported), 'exportedBytes': total, 'withheld': withheld, 'rawRetention': 'Exact selected audited raw bytes are durable in uploaded artifact. Withheld raw remains only on ephemeral runner; no durable retention or reconstruction is claimed for withheld data.'}
    write(public / 'export-audit.json', {'files': exported, 'withheld': withheld})
    write(public / 'controller-result.json', result)
    files = [{'path': str(path.relative_to(public)), 'bytes': path.stat().st_size, 'sha256': digest(path)} for path in sorted(public.rglob('*')) if path.is_file() and not path.is_symlink()]
    write(public / 'evidence-manifest.json', {'files': files})
