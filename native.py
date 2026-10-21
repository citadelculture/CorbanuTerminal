#!/usr/bin/env python3
"""Bounded ordinary schema generation support, never a product qualification claim."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import time
import xml.etree.ElementTree as ET
from controller import digest, need, safe_path, write

GIB = 1024**3
GENERATOR = 'schema_fixtures_tests::write_schema_fixtures_from_env'
PACKAGE = 'codex-app-server-protocol'
STABLE = 'codex-rs/app-server-protocol/schema/precomputed/app-server-exports-stable.json.zst'
DENY_CLOSURE = {'codex-core', 'codex-app-server', 'codex-tui', 'codex-cli', 'codex-wallet-daemon', 'codex-rmcp-client', 'codex-code-mode-host', 'v8'}


def generator_command():
    return ['just', 'test', '-p', PACKAGE, '--lib', '--locked', '--offline', '--retries', '0', '--test-threads', '1', '--color', 'never', '-E', 'test(=' + GENERATOR + ')', '--run-ignored', 'only', '--no-tests', 'fail', '--status-level', 'pass', '--final-status-level', 'all', '--success-output', 'immediate', '--failure-output', 'immediate']


def compile_command():
    return ['just', 'test', '-p', PACKAGE, '--lib', '--locked', '--offline', '--retries', '0', '--color', 'never', '-E', 'none()', '--no-tests', 'pass']


def host_preflight():
    memory = Path('/proc/meminfo').read_text()
    match = re.search(r'^MemTotal:\s+(\d+) kB$', memory, re.M)
    need(match is not None, 'memory_identity_missing')
    mem = int(match.group(1)) * 1024
    cpus = os.cpu_count()
    need(mem >= 12 * GIB and cpus is not None and cpus >= 4, 'native_host_capacity')
    return {'memTotalBytes': mem, 'logicalCpus': cpus, 'realUid': os.getuid(), 'effectiveUid': os.geteuid(), 'ownerHostFloorsUnchanged': True}


def usage(root, max_entries=350000, seconds=10):
    """No-follow fd walk of owned cache/target only; no shared-store inventory."""
    total, count = 0, 0
    deadline = time.monotonic() + seconds
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        mode = root.lstat().st_mode
    except FileNotFoundError:
        return {'bytes': 0, 'entries': 0}
    need(stat.S_ISDIR(mode), 'usage_root_not_directory')
    def walk(fd, depth):
        nonlocal total, count
        need(depth <= 64, 'usage_depth_bound')
        for name in os.listdir(fd):
            count += 1
            need(count <= max_entries and time.monotonic() < deadline, 'usage_scan_bound')
            try:
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                continue  # Cargo may atomically remove/rename temporary files.
            if stat.S_ISDIR(st.st_mode):
                try:
                    child = os.open(name, flags, dir_fd=fd)
                except FileNotFoundError:
                    continue
                try:
                    actual = os.fstat(child)
                    need((actual.st_dev, actual.st_ino) == (st.st_dev, st.st_ino), 'usage_directory_changed')
                    walk(child, depth + 1)
                finally:
                    os.close(child)
            elif stat.S_ISREG(st.st_mode):
                total += st.st_size
            elif not stat.S_ISLNK(st.st_mode):
                raise RuntimeError('usage_special_entry')
    fd = os.open(root, flags)
    try:
        walk(fd, 0)
    finally:
        os.close(fd)
    return {'bytes': total, 'entries': count}


def group_rss(pgid, proc=Path('/proc')):
    # The worker starts a fresh session. Nextest's test-specific process groups
    # stay in this same session and must be included in resource accounting.
    rows = session_members(pgid, proc)
    return {'bytes': sum(r['rssBytes'] for r in rows), 'pids': [r['pid'] for r in rows], 'scope': 'owned-session'}


def check_resource_sample(root, pgid):
    cache = usage(root / 'cargo-home')
    target = usage(root / 'generation-target')
    group = group_rss(pgid)
    need(cache['bytes'] <= 8 * GIB, 'cargo_cache_bound')
    need(target['bytes'] <= 20 * GIB, 'native_target_bound')
    need(group['bytes'] <= 10 * GIB, 'owned_group_memory_bound')
    return {'cargoHome': cache, 'generationTarget': target, 'ownedGroupRss': group}


def fresh_target(root, free):
    need(free >= 30 * GIB, 'fresh_native_compile_below_30GiB')
    try:
        root.lstat()
    except FileNotFoundError:
        pass
    else:
        raise RuntimeError('qualification_target_not_fresh')
    root.mkdir(mode=0o700)
    need(not any(root.iterdir()), 'qualification_target_not_empty')
    return {'path': root.name, 'freeBytes': free, 'empty': True}


def validate_lock(path):
    import tomllib
    value = tomllib.loads(path.read_text())
    rows = []
    for package in value['package']:
        source = package.get('source')
        if source is None:
            continue
        if source == 'registry+https://github.com/rust-lang/crates.io-index':
            need(re.fullmatch('[a-f0-9]{64}', package.get('checksum', '')), 'registry_checksum_missing')
        else:
            need(re.fullmatch(r'git\+https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\?[^#\s]*)?#[a-f0-9]{40}', source), 'nonpublic_locked_source')
        rows.append({'name': package['name'], 'version': package['version'], 'source': source, 'checksum': package.get('checksum')})
    return rows


def cargo_cache_inventory(home, lock_rows):
    """Hash acquired registry archives and exact public git source revision references."""
    expected = {(r['name'] + '-' + r['version'] + '.crate'): r['checksum'] for r in lock_rows if r['checksum']}
    rows = []
    cache = safe_path(home, 'registry/cache')
    if cache.exists():
        need(stat.S_ISDIR(cache.lstat().st_mode), 'registry_cache_type')
        for repository in cache.iterdir():
            need(stat.S_ISDIR(repository.lstat().st_mode), 'registry_cache_type')
            for p in repository.iterdir():
                need(stat.S_ISREG(p.lstat().st_mode) and p.name in expected, 'unlocked_registry_archive')
                h = digest(p)
                need(h == expected[p.name], 'registry_archive_checksum')
                rows.append({'path': str(p.relative_to(home)), 'bytes': p.stat().st_size, 'sha256': h})
    need(rows, 'registry_cache_empty')
    return {'registryArchives': sorted(rows, key=lambda r: r['path']), 'gitSources': [r for r in lock_rows if r['source'].startswith('git+')], 'gitRevisionVerification': 'cargo fetch --locked authenticates these exact revisions; offline cargo tree validates source availability. No compiled cache reuse.'}


def check_closure(data):
    names = set()
    for line in data.decode().splitlines():
        if not line.strip():
            continue
        name = line.split()[0]
        need(re.fullmatch('[A-Za-z0-9_-]+', name), 'closure_output_shape')
        names.add(name)
    need(PACKAGE in names and 'codex-protocol' in names, 'closure_root_missing')
    need(not names.intersection(DENY_CLOSURE), 'unexpected_heavy_closure')
    return {'packages': sorted(names), 'helperBuildExpected': False}


def schema_paths(pins):
    policy = pins['generatedOutputPolicy']
    need(policy.get('allowAddedFiles') is False and policy.get('existingRegularPathsOnly') is True, 'schema_output_policy_not_exact')
    names = policy['paths']
    need(names and len(names) <= 5000 and len(names) == len(set(names)) and STABLE in names, 'schema_inventory_bound')
    for name in names:
        need(not Path(name).is_absolute() and '..' not in Path(name).parts, 'schema_inventory_path')
        need(name == STABLE or (name.startswith('codex-rs/app-server-protocol/schema/typescript/') and name.endswith('.ts')) or (name.startswith('codex-rs/app-server-protocol/schema/json/') and name.endswith('.json')), 'schema_inventory_path')
    return sorted(names)


def snapshot_schema(source, export, label, pins):
    names = schema_paths(pins)
    roots = ['codex-rs/app-server-protocol/schema/typescript', 'codex-rs/app-server-protocol/schema/json']
    actual = []
    count = 0
    deadline = time.monotonic() + 60
    for name in roots:
        top = safe_path(source, name)
        need(stat.S_ISDIR(top.lstat().st_mode), 'schema_root_not_directory')
        pending = [top]
        while pending:
            folder = pending.pop()
            for p in folder.iterdir():
                count += 1
                need(count <= 10000 and time.monotonic() < deadline, 'schema_walk_bound')
                st = p.lstat()
                if stat.S_ISDIR(st.st_mode):
                    pending.append(p)
                else:
                    need(stat.S_ISREG(st.st_mode), 'schema_nonregular_entry')
                    actual.append(str(p.relative_to(source)))
    need(sorted(actual + [STABLE]) == names, 'schema_inventory_changed')
    rows = {}
    total = 0
    for name in names:
        p = safe_path(source, name)
        st = p.lstat()
        need(stat.S_ISREG(st.st_mode) and st.st_size <= 2 * 1024**2, 'schema_file_type_or_size')
        total += st.st_size
        need(total <= 64 * 1024**2, 'schema_total_size')
        target = export / label / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(p, target)
        need(digest(p) == digest(target), 'schema_copy_mismatch')
        rows[name] = {'bytes': st.st_size, 'sha256': digest(target)}
    write(export / (label + '.json'), rows)
    return rows


def retain_junit(source, raw, label="generator"):
    p = safe_path(source, 'codex-rs/target/nextest/local/junit.xml')
    need(stat.S_ISREG(p.lstat().st_mode) and p.stat().st_size <= 8 * 1024**2, 'junit_missing_type_or_size')
    data = p.read_bytes()
    need(b'<!DOCTYPE' not in data and b'<!ENTITY' not in data, 'junit_external_entity')
    need(label in ('generator', 'compile'), 'junit_label')
    out = raw / (label + '-junit.xml')
    out.write_bytes(data)
    return {'path': out.name, 'bytes': len(data), 'sha256': digest(out)}


def validate_generator(xml_data, log_data):
    need(len(xml_data) <= 8 * 1024**2 and b'<!DOCTYPE' not in xml_data and b'<!ENTITY' not in xml_data, 'unsafe_junit')
    doc = ET.fromstring(xml_data)
    need(doc.tag == 'testsuites', 'junit_root_shape')
    suites = list(doc.iter('testsuite'))
    need(len(suites) == 1 and suites[0].get('name') == PACKAGE, 'generator_suite_identity')
    for node in (doc, suites[0]):
        for key, expected in (('tests', '1'), ('failures', '0'), ('errors', '0')):
            need(node.get(key) == expected, 'generator_junit_totals')
        need(node.get('skipped', '0') == '0', 'generator_junit_skipped')
    cases = list(doc.iter('testcase'))
    need(len(cases) == 1, 'generator_case_count')
    case = cases[0]
    need(case.get('name') == GENERATOR and case.get('classname') == PACKAGE, 'generator_case_identity')
    need(not any(c.tag in ('failure', 'error', 'skipped') or 'rerun' in c.tag.lower() or 'flaky' in c.tag.lower() for c in case.iter() if c is not case), 'generator_case_not_single_pass')
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', log_data.decode(errors='replace'))
    progress = text.split('Summary', 1)[0]
    rows = []
    for line in progress.splitlines():
        if re.match(r'\s*(PASS|FAIL|SKIP|TIMEOUT|LEAK|SLOW|TRY\s+\d+)\s', line):
            if line.lstrip().startswith('SLOW '):
                continue
            match = re.fullmatch(r'\s*PASS\s+\[[^\]\r\n]+\]\s+(?:\(\s*(\d+)/\s*(\d+)\)\s+)?codex-app-server-protocol\s+' + re.escape(GENERATOR) + r'\s*', line)
            need(match is not None, 'unexpected_generator_progress')
            if match.group(1):
                need((match.group(1), match.group(2)) == ('1', '1'), 'generator_ordinal')
            rows.append(line)
    need(len(rows) == 1, 'generator_progress_count')
    need(not re.search(r'(?im)^.*(?:skipping test|test skipped|network.*skip|skip.*network).*$|running 0 tests', text), 'body_skip_marker')
    return {'expected': 1, 'passed': 1, 'skipped': 0, 'retried': 0, 'name': GENERATOR, 'package': PACKAGE, 'productQualified': False}


def elf_file(path):
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode):
        return False
    with path.open('rb') as f:
        header = f.read(20)
    return len(header) == 20 and header[:6] == b'\x7fELF\x02\x01' and int.from_bytes(header[16:18], 'little') in (2, 3) and int.from_bytes(header[18:20], 'little') == 62


def capture_binary(target, raw, run):
    directory = safe_path(target, 'debug/deps')
    need(stat.S_ISDIR(directory.lstat().st_mode), 'binary_directory_type')
    candidates = [p for p in directory.glob('codex_app_server_protocol-*') if elf_file(p) and p.stat().st_mode & 0o111]
    need(len(candidates) == 1, 'generator_binary_ambiguity')
    binary = candidates[0]
    records = []
    pending = [binary]
    copied = set()
    total = 0
    library_cache = run(['/sbin/ldconfig', '-p'], 'system-library-map', capture=True).decode()
    mapping = {}
    for line in library_cache.splitlines():
        m = re.match(r'\s*(\S+)\s+\([^)]*x86-64[^)]*\)\s+=>\s+(/\S+)\s*$', line)
        if m:
            mapping.setdefault(m.group(1), []).append(m.group(2))
    while pending:
        p = pending.pop(0)
        # Only declared public system libraries may resolve symlinks. Source
        # fixtures and all owned exported paths continue to use no-follow checks.
        if p != binary:
            p = p.resolve(strict=True)
            need(str(p).startswith('/usr/lib/x86_64-linux-gnu/') or str(p).startswith('/lib/x86_64-linux-gnu/'), 'runtime_library_path')
        if str(p) in copied:
            continue
        need(elf_file(p) and len(copied) < 32, 'runtime_library_type_or_count')
        copied.add(str(p))
        total += p.stat().st_size
        need(total <= 2 * GIB, 'binary_capture_bound')
        label = 'test-executable' if p == binary else 'runtime-' + p.name
        destination = raw / 'native-binaries' / label
        destination.parent.mkdir(exist_ok=True)
        need(not destination.exists(), 'binary_name_collision')
        shutil.copyfile(p, destination)
        need(digest(p) == digest(destination), 'binary_copy_mismatch')
        records.append({'path': str(destination.relative_to(raw)), 'bytes': p.stat().st_size, 'sha256': digest(destination), 'mode': oct(stat.S_IMODE(p.stat().st_mode)), 'role': 'generator-test' if p == binary else 'system-runtime', 'source': '<GENERATION_TARGET>/' + str(p.relative_to(target)) if p == binary else str(p)})
        out = run(['/usr/bin/readelf', '-d', str(p)], 'elf-dynamic-' + str(len(records)), capture=True).decode()
        for name in re.findall(r'\(NEEDED\).*\[([^\]]+)\]', out):
            paths = mapping.get(name, [])
            resolved = set(str(Path(x).resolve(strict=True)) for x in paths)
            need(len(resolved) == 1, 'runtime_library_missing_or_ambiguous')
            pending.append(Path(next(iter(resolved))))
    program = run(['/usr/bin/readelf', '-l', str(binary)], 'elf-program', capture=True).decode()
    interpreter = re.findall(r'Requesting program interpreter:\s*([^\]]+)\]', program)
    need(len(interpreter) == 1, 'elf_interpreter_missing')
    interp = Path(interpreter[0]).resolve(strict=True)
    need(str(interp).startswith('/usr/lib/x86_64-linux-gnu/') or str(interp).startswith('/lib/x86_64-linux-gnu/'), 'elf_interpreter_path')
    if str(interp) not in copied:
        need(elf_file(interp) and total + interp.stat().st_size <= 2 * GIB, 'elf_interpreter_bound')
        dest = raw / 'native-binaries' / ('runtime-' + interp.name)
        need(not dest.exists(), 'binary_name_collision')
        shutil.copyfile(interp, dest)
        records.append({'path': str(dest.relative_to(raw)), 'bytes': dest.stat().st_size, 'sha256': digest(dest), 'mode': oct(stat.S_IMODE(interp.stat().st_mode)), 'role': 'system-interpreter', 'source': str(interp)})
    write(raw / 'native-binaries.json', {'files': records, 'executableSha256': digest(binary), 'productQualified': False})
    return {'files': records, 'executableSha256': digest(binary), 'targetRelativePath': str(binary.relative_to(target))}


def runtime_store_inventory(source, require_junit=False):
    """Only the pinned Nextest workspace store is permitted inside ignored target."""
    target = safe_path(source, 'codex-rs/target')
    try:
        st = target.lstat()
    except FileNotFoundError:
        need(not require_junit, 'runtime_junit_missing')
        return []
    need(stat.S_ISDIR(st.st_mode), 'runtime_store_not_directory')
    expected_dirs = {'nextest', 'nextest/local'}
    rows = []
    pending = [target]
    while pending:
        folder = pending.pop()
        for path in folder.iterdir():
            name = str(path.relative_to(target))
            st = path.lstat()
            if stat.S_ISDIR(st.st_mode):
                need(name in expected_dirs, 'unexpected_runtime_directory')
                pending.append(path)
            else:
                need(stat.S_ISREG(st.st_mode) and name == 'nextest/local/junit.xml' and st.st_size <= 8 * 1024**2, 'unexpected_runtime_output')
                rows.append({'path': name, 'bytes': st.st_size, 'sha256': digest(path)})
    need(not require_junit or len(rows) == 1, 'runtime_junit_missing')
    return rows


def decode_stable(source_file, output, run, phase):
    need(stat.S_ISREG(source_file.lstat().st_mode), 'stable_input_not_regular')
    need(not output.exists(), 'decoded_output_preexisting')
    run(['/usr/bin/zstd', '--decompress', '--no-progress', '--output', str(output), str(source_file)], phase, timeout=90)
    need(stat.S_ISREG(output.lstat().st_mode) and output.stat().st_size <= 16 * 1024**2, 'decoded_schema_size')
    value = json.loads(output.read_text())
    need(isinstance(value, dict), 'decoded_schema_shape')
    return {'path': output.name, 'bytes': output.stat().st_size, 'sha256': digest(output), 'compressedSha256': digest(source_file)}


def cleanup_runtime_store(source, raw):
    rows = runtime_store_inventory(source)
    receipt = {'filesBefore': rows, 'rawXml': None, 'removed': False}
    target = source / 'codex-rs/target'
    if rows:
        p = safe_path(source, 'codex-rs/target/nextest/local/junit.xml')
        data = p.read_bytes()
        need(hashlib.sha256(data).hexdigest() == rows[0]['sha256'], 'runtime_junit_changed')
        out = raw / 'controller-junit.xml'
        out.write_bytes(data)
        receipt['rawXml'] = {'path': out.name, 'bytes': len(data), 'sha256': digest(out)}
        p.unlink()
    # The inventory admitted only these exact synthetic runtime directories.
    # No recursive deletion and no symlink/foreign-path traversal.
    for name in ('nextest/local', 'nextest', '.'):
        p = target / name
        try:
            st = p.lstat()
        except FileNotFoundError:
            continue
        need(stat.S_ISDIR(st.st_mode), 'runtime_cleanup_directory_type')
        p.rmdir()
    receipt['removed'] = not target.exists()
    return receipt


def session_members(session_id, proc=Path('/proc')):
    """Inspect stat identity only; do not read another process's environment."""
    rows = []
    deadline = time.monotonic() + 5
    scanned = 0
    for path in proc.iterdir():
        scanned += 1
        need(scanned <= 32768 and time.monotonic() < deadline, 'process_inventory_bound')
        if not path.name.isdigit():
            continue
        try:
            text = (path / 'stat').read_text()
        except FileNotFoundError:
            continue
        except PermissionError:
            raise RuntimeError('session_membership_unknown') from None
        fields = text[text.rfind(')') + 2:].split()
        need(len(fields) >= 22, 'proc_stat_shape')
        if int(fields[3]) == session_id:
            rows.append({'pid': int(path.name), 'startTicks': int(fields[19]), 'state': fields[0], 'pgid': int(fields[2]), 'rssBytes': int(fields[21]) * os.sysconf('SC_PAGE_SIZE')})
    need(len(rows) <= 512, 'owned_process_count_bound')
    return sorted(rows, key=lambda row: row['pid'])


def cleanup_session(session_id, *, seconds=25):
    import signal
    need(session_id > 1 and session_id != os.getsid(0), 'wrong_owned_session')
    started = time.monotonic()
    receipt = {'sessionId': session_id, 'ownedSessionGone': False, 'signals': []}
    for sig, grace in ((signal.SIGTERM, 10), (signal.SIGKILL, 10)):
        rows = session_members(session_id)
        for row in rows:
            need(time.monotonic() < started + seconds, 'owned_session_cleanup_deadline')
            # Revalidate pid birth identity and session immediately before signal.
            current = {x['pid']: x for x in session_members(session_id)}.get(row['pid'])
            if current is None:
                continue
            need(current['startTicks'] == row['startTicks'], 'owned_pid_reused')
            try:
                os.kill(row['pid'], sig)
                receipt['signals'].append({'pid': row['pid'], 'signal': sig.name})
            except ProcessLookupError:
                pass
        deadline = min(started + seconds, time.monotonic() + grace)
        while time.monotonic() < deadline:
            if not session_members(session_id):
                receipt['ownedSessionGone'] = True
                return receipt
            time.sleep(0.2)
    receipt['remaining'] = session_members(session_id)
    receipt['ownedSessionGone'] = not receipt['remaining']
    return receipt
