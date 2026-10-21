"""Strict offline evidence accounting; never runs product code."""
import hashlib
import json
import re
import xml.etree.ElementTree as ET


class Hold(RuntimeError):
    pass


def need(value, reason):
    if not value:
        raise Hold(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def normalize(data, replacements):
    text = data.decode('utf-8', errors='strict')
    for old, new in sorted(replacements.items(), key=lambda x: -len(x[0])):
        text = text.replace(old, new)
    # No raw environment/startup dump is a valid diagnostic export.
    need(not re.search(r'/Users/|[A-Za-z]:\\Users\\|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_|-----BEGIN .*PRIVATE KEY|(?im:^)(?:HOME|PATH|PWD|USER|SHELL|CARGO_HOME|GITHUB_[A-Z0-9_]+|ACTIONS_[A-Z0-9_]+|OPENAI_API_KEY|ANTHROPIC_API_KEY)=', text), 'unsafe_public_diagnostic')
    return text.encode()


def normalize_xml(data, replacements):
    need(len(data) <= 16*1024*1024 and b'<!DOCTYPE' not in data.upper() and b'<!ENTITY' not in data.upper(), 'unsafe_xml')
    root = ET.fromstring(data)
    for element in root.iter():
        for key, value in list(element.attrib.items()):
            element.set(key, normalize(value.encode(), replacements).decode())
        if element.text is not None:
            element.text = normalize(element.text.encode(), replacements).decode()
        if element.tail is not None:
            element.tail = normalize(element.tail.encode(), replacements).decode()
    return ET.tostring(root, encoding='utf-8', xml_declaration=True)


def parse_progress(text, expected):
    text = re.sub(r'\x1b\[[0-9;]*m', '', text)
    need(text.count('Test isolation: disposable profile; native keyring disabled (debug lane)') == 1, 'ordinary_wrapper_marker')
    need(not re.search(r'(?i)\b(?:skipping|body.?skip|native prompt|keychain prompt)\b|\bRETRY\b|\bTRY [2-9]', text), 'body_skip_retry_or_prompt')
    summaries = re.findall(r'^\s*Summary\s+\[[^\]]+\]\s+(\d+) tests? run:\s*(.*)$', text, re.M)
    need(len(summaries) == 1, 'summary_missing_or_duplicate')
    before = re.split(r'^\s*Summary\s+', text, maxsplit=1, flags=re.M)[0]
    pattern = r'^\s*(PASS|FAIL|SKIP|TIMEOUT|LEAK|FLAKY)\s+\[[^\]]+\]\s+(?:\(\s*(\d+)\s*/\s*(\d+)\s*\)\s+)?(\S+)\s+(placeholder_journal::tests::\S+)\s*$'
    records = []
    for match in re.finditer(pattern, before, re.M):
        status, ordinal, total, binary, name = match.groups()
        need(binary == 'codex-linux-sandbox', 'wrong_binary_identity')
        need(name in expected, 'unexpected_case')
        if ordinal is not None:
            need(1 <= int(ordinal) <= len(expected) and int(total) == len(expected), 'invalid_ordinal')
        need(name not in {r['name'] for r in records}, 'duplicate_execution_record')
        records.append({'name': name, 'status': status, 'binary': binary})
    need(len(records) == len(expected) and {r['name'] for r in records} == set(expected), 'execution_identity_mismatch')
    need(all(r['status'] in ('PASS', 'FAIL') for r in records), 'selected_not_executed_cleanly')
    need(int(summaries[0][0]) == len(expected), 'summary_execution_count')
    passed = sum(r['status'] == 'PASS' for r in records)
    failed = sum(r['status'] == 'FAIL' for r in records)
    details = summaries[0][1]
    count = lambda word: int((re.search(r'\b(\d+) '+word+r'\b', details) or [None, '0'])[1])
    need(count('passed') == passed and count('failed') == failed and not re.search(r'flaky|leaked|timed out|cancelled', details), 'summary_outcomes_mismatch')
    return records


def parse_junit(data, expected):
    need(len(data) <= 16*1024*1024 and b'<!DOCTYPE' not in data.upper() and b'<!ENTITY' not in data.upper(), 'unsafe_xml')
    root = ET.fromstring(data)
    rows = []
    for case in root.iter('testcase'):
        name = case.get('name'); cls = case.get('classname')
        need(name in expected and cls == 'codex-linux-sandbox', 'junit_identity')
        need(name not in {r['name'] for r in rows}, 'junit_duplicate')
        need(case.find('skipped') is None and case.find('error') is None, 'junit_skip_or_error')
        need(not any('rerun' in item.tag.lower() or 'flaky' in item.tag.lower() for item in case.iter()), 'junit_retry_or_flaky')
        failures = case.findall('failure'); need(len(failures) <= 1, 'junit_multiple_failure')
        captures = [*failures, *case.findall('system-out'), *case.findall('system-err')]
        rows.append({'name': name, 'status': 'FAIL' if failures else 'PASS', 'failureText': ''.join(failures[0].itertext()) if failures else '', 'caseCapture': '\n'.join(''.join(item.itertext()) for item in captures)})
    need(len(rows) == len(expected), 'junit_case_count')
    return rows


def classify(log, xml, expected, failed_case=None, location=None, exit_code=0):
    progress = parse_progress(log, expected); junit = parse_junit(xml, expected)
    need({r['name']:r['status'] for r in progress} == {r['name']:r['status'] for r in junit}, 'junit_progress_conflict')
    failures = [r for r in junit if r['status'] == 'FAIL']
    if failed_case:
        need(exit_code == 100 and len(failures) == 1 and failures[0]['name'] == failed_case, 'unexpected_baseline_outcome')
        need(location in log and 'assertion failed' in log, 'baseline_assertion_location_missing')
        capture = failures[0]['caseCapture']
        need(location in capture and 'assertion failed' in capture, 'baseline_case_assertion_missing')
    else:
        need(exit_code == 0 and not failures, 'candidate_failure')
    return {'executed': len(progress), 'passed': len(progress)-len(failures), 'failed': len(failures), 'records': progress, 'junitAgrees': True, 'selectedSkipped': 0, 'retries': 0}
