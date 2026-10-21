#!/usr/bin/env python3
"""Bounded schema generator through the ordinary test wrapper, then full formatting."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import urllib.request
from controller import digest, failure_code, need, safe_path, write

HERE = Path(__file__).resolve().parent


def regular(path):
    return stat.S_ISREG(path.lstat().st_mode)


def subject_path(source, relative):
    name = Path(relative)
    need(not name.is_absolute() and ".." not in name.parts, "subject_path_escape")
    current = source
    need(stat.S_ISDIR(current.lstat().st_mode), "subject_root_not_directory")
    for part in name.parts[:-1]:
        current /= part
        need(stat.S_ISDIR(current.lstat().st_mode), "subject_parent_not_directory")
    return source / name


def link_records(source, rows, pins):
    expected = {row["path"]: row for row in pins}
    actual = {}
    for row in rows.split(b"\0"):
        if not row:
            continue
        metadata, name = row.split(b"\t", 1)
        mode, kind, blob = metadata.decode().split()
        if mode != "120000":
            continue
        path = os.fsdecode(name)
        need(path in expected, "unexpected_tracked_symlink")
        entry = subject_path(source, path)
        need(stat.S_ISLNK(entry.lstat().st_mode), "symlink_replaced_by_file")
        target = os.fsencode(os.readlink(entry))
        record = {"path": path, "mode": mode, "blob": blob, "targetSha256": hashlib.sha256(target).hexdigest(), "targetBytes": len(target)}
        need(record == expected[path], "symlink_identity_mismatch")
        # The pinned external credential-looking fixture is inert source data.
        # Never resolve, stat, open, copy or publish its target or target text.
        actual[path] = record
    need(set(actual) == set(expected), "tracked_symlink_inventory_mismatch")
    return list(actual.values())


def safe_extract(archive, destination):
    destination.mkdir(exist_ok=False)
    with tarfile.open(archive) as source:
        members = source.getmembers()
        need(len(members) <= 50000 and sum(m.size for m in members) <= 2 * 1024**3, "tool_archive_expansion_bound")
        for member in members:
            name = PurePosixPath(member.name)
            need(not name.is_absolute() and ".." not in name.parts, "tool_archive_path_escape")
            need(member.isfile() or member.isdir() or member.issym() or member.islnk(), "tool_archive_special_type")
            if member.issym() or member.islnk():
                target = PurePosixPath(member.linkname)
                need(not target.is_absolute(), "tool_archive_absolute_link")
                joined = name.parent / target if member.issym() else target
                depth = 0
                for part in joined.parts:
                    depth += -1 if part == ".." else 0 if part == "." else 1
                    need(depth >= 0, "tool_archive_link_escape")
        source.extractall(destination, members=members, filter="data")



def check_scope(paths, allowed):
    need(set(paths) <= set(allowed), 'unexpected_tracked_source_delta')


def snapshot_selected(source, export, label, candidate_files):
    records = {}
    for name in candidate_files:
        path = subject_path(source, name)
        need(regular(path) and path.stat().st_size <= 2 * 1024**2, 'unsafe_selected_source')
        destination = export / label / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
        need(digest(path) == digest(destination), 'selected_copy_mismatch')
        records[name] = {'sha256': digest(destination), 'bytes': destination.stat().st_size}
    write(export / (label + '.json'), records)
    return records


def tree_entries(raw):
    rows = []
    for record in raw.split(b'\0'):
        if not record:
            continue
        metadata, name = record.split(b'\t', 1)
        mode, kind, blob = metadata.decode().split()
        need(kind == 'blob' and mode in ('100644', '100755', '120000'), 'unsupported_tree_entry')
        rows.append({'path': os.fsdecode(name), 'mode': mode, 'blob': blob})
    names = [row['path'] for row in rows]
    need(len(names) == len(set(names)) and len(names) <= 60000, 'tree_entry_bound_or_duplicate')
    return rows


def snapshot_tree(source, entries, symlinks):
    links = {x['path']: x for x in symlinks}
    deadline = time.monotonic() + 120
    result = {}
    for row in entries:
        need(time.monotonic() < deadline, 'tree_snapshot_deadline')
        name = row['path']
        path = subject_path(source, name)
        st = path.lstat()
        if row['mode'] == '120000':
            need(stat.S_ISLNK(st.st_mode) and name in links, 'tree_link_type_or_scope')
            target = os.fsencode(os.readlink(path))
            identity = {'path': name, 'mode': row['mode'], 'blob': row['blob'], 'targetSha256': hashlib.sha256(target).hexdigest(), 'targetBytes': len(target)}
            need(identity == links[name], 'tree_link_identity_changed')
            result[name] = {'type': 'symlink', 'mode': row['mode'], 'bytes': len(target), 'sha256': identity['targetSha256']}
        else:
            need(stat.S_ISREG(st.st_mode), 'tree_regular_type_changed')
            mode = '100755' if st.st_mode & 0o111 else '100644'
            need(mode == row['mode'], 'tree_file_mode_changed')
            result[name] = {'type': 'regular', 'mode': mode, 'bytes': st.st_size, 'sha256': digest(path)}
    need({name for name, row in result.items() if row['type'] == 'symlink'} == set(links), 'tree_link_inventory_changed')
    return result


def compare_snapshots(before, after, allowed):
    need(set(before) == set(after), 'tracked_inventory_changed')
    changed = []
    for name in before:
        need(before[name]['type'] == after[name]['type'] and before[name]['mode'] == after[name]['mode'], 'tracked_type_or_mode_changed')
        if before[name] != after[name]:
            changed.append(name)
    check_scope(changed, allowed)
    return sorted(changed)


def metadata_inventory(root):
    records = []
    if root.exists() or root.is_symlink():
        need(stat.S_ISDIR(root.lstat().st_mode), 'metadata_root_not_directory')
        for path in sorted(root.rglob('*')):
            mode = path.lstat().st_mode
            name = str(path.relative_to(root))
            if stat.S_ISDIR(mode):
                records.append({'path': name, 'type': 'directory'})
            else:
                need(stat.S_ISREG(mode) and name == '.rustc_info.json' and path.stat().st_size <= 1024**2, 'unexpected_cargo_target_output')
                records.append({'path': name, 'type': 'regular', 'bytes': path.stat().st_size, 'sha256': digest(path)})
    return records


def main(root, export):
    source = HERE.parent / 'subject'
    pins = json.loads((HERE / 'source-pins.json').read_text())
    tools = json.loads((HERE / 'tool-pins.json').read_text())
    result = {'schema': 'issue1248-stagea-worker-v1', 'completed': False, 'failureCode': None, 'productQualified': False, 'nativeCounts': {'compileInvocations': 0, 'compileSucceeded': 0, 'generatorInvocations': 0, 'generatorBodiesVerified': 0}, 'productRegressionBodies': 0, 'base': pins['base'], 'phases': [], 'downloads': []}
    env = os.environ.copy()
    env.update({'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0', 'GIT_ASKPASS': '/usr/bin/false', 'GIT_NO_LAZY_FETCH': '1', 'CARGO_HOME': str(root / 'cargo-home'), 'CARGO_TARGET_DIR': str(root / 'metadata-target'), 'CARGO_NET_OFFLINE': 'true', 'UV_CACHE_DIR': str(root / 'cache/uv'), 'XDG_CACHE_HOME': str(root / 'cache/xdg'), 'UV_PYTHON': sys.executable, 'UV_PYTHON_DOWNLOADS': 'never'})
    need(not any(key in env for key in ('GITHUB_TOKEN', 'GH_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'BUILDBUDDY_API_KEY')), 'unexpected_credential_environment')
    command_number = 0
    entries = None
    pre_format = None
    generation_tree = None
    from native import (STABLE, PACKAGE, compile_command, generator_command, schema_paths, snapshot_schema, validate_lock, cargo_cache_inventory, check_closure, fresh_target, retain_junit, runtime_store_inventory, validate_generator, capture_binary, decode_stable, usage)
    allowed_final = pins['allowedChangedFiles'] + schema_paths(pins)
    selected_final = {**pins['candidateFiles'], STABLE: None}
    env.update({'NEXTEST_USER_CONFIG_FILE': 'none', 'CARGO_INCREMENTAL': '0', 'CARGO_BUILD_JOBS': '2', 'CARGO_PROFILE_DEV_DEBUG': '0', 'CARGO_PROFILE_TEST_DEBUG': '0', 'CARGO_PROFILE_DEV_DEBUG_ASSERTIONS': 'true', 'CARGO_PROFILE_TEST_DEBUG_ASSERTIONS': 'true'})

    def run(argv, phase, timeout=120, capture=False, cwd=source):
        nonlocal command_number
        command_number += 1
        start = time.monotonic()
        log = export / f'{command_number:02d}-{phase}.log'
        row = {'phase': phase, 'command': [str(x).replace(str(root), '<RUN_ROOT>').replace(str(source), '<SUBJECT>').replace(str(HERE), '<METHOD>') for x in argv], 'exitCode': None, 'log': log.name}
        result['phases'].append(row)
        write(export / 'worker-progress.json', {'activePhase': phase, 'command': row['command']})
        process = None
        try:
            with log.open('wb') as handle:
                process = subprocess.run(argv, cwd=cwd, env=env, stdout=handle, stderr=subprocess.STDOUT, timeout=timeout)
            row['exitCode'] = process.returncode
        except BaseException as error:
            if isinstance(error, subprocess.TimeoutExpired):
                result['processTimeout'] = True
            row['failureCode'] = failure_code(error)
            raise
        finally:
            row['elapsedSeconds'] = round(time.monotonic() - start, 3)
            if log.exists():
                row['logSha256'] = digest(log)
                row['logBytes'] = log.stat().st_size
        need(log.stat().st_size <= 64 * 1024**2, 'command_log_bound')
        need(process.returncode == 0, 'command_failed_' + phase.replace('-', '_'))
        return log.read_bytes() if capture else b''

    def git(*arguments):
        return run(['git', *arguments], 'git-' + arguments[0], capture=True)

    def selected_hashes():
        answer = {}
        for name in pins['candidateFiles']:
            path = subject_path(source, name)
            need(regular(path), 'selected_source_not_regular')
            answer[name] = digest(path)
        return answer

    try:
        need(source.is_dir() and not source.is_symlink(), 'subject_not_checkout')
        need(git('rev-parse', 'HEAD').decode().strip() == pins['base'], 'subject_head_mismatch')
        need(git('rev-parse', 'HEAD^{tree}').decode().strip() == pins['baseTree'], 'subject_tree_mismatch')
        need(not git('status', '--porcelain=v1', '--untracked-files=all'), 'dirty_initial_subject')
        tree = git('ls-tree', '-r', '-z', '--full-tree', 'HEAD')
        need(len(tree) == pins['baseGitLsTreeBytes'] and hashlib.sha256(tree).hexdigest() == pins['baseGitLsTreeSha256'], 'full_git_tree_mismatch')
        entries = tree_entries(tree)
        result['symlinksBefore'] = link_records(source, tree, pins['symlinks'])
        write(export / 'source-layout.json', {'baseTree': pins['baseTree'], 'gitTreeSha256': hashlib.sha256(tree).hexdigest(), 'entries': len(entries), 'symlinks': result['symlinksBefore']})
        for name, expected in pins['baseFiles'].items():
            path = subject_path(source, name)
            need(regular(path) and digest(path) == expected, 'baseline_source_hash_mismatch')
        base_tree = snapshot_tree(source, entries, pins['symlinks'])
        write(export / 'base-tree.json', base_tree)
        snapshot_selected(source, export, 'base-source', selected_final)
        result['schemaBefore'] = snapshot_schema(source, export, 'schema-before', pins)
        need(not runtime_store_inventory(source), 'preexisting_nextest_store')
        need(digest(HERE / 'subject.patch') == pins['patchSha256'], 'patch_hash_mismatch')
        git('apply', '--check', str(HERE / 'subject.patch'))
        git('apply', str(HERE / 'subject.patch'))
        result['candidateBefore'] = selected_hashes()
        need(result['candidateBefore'] == pins['candidateFiles'], 'candidate_source_hash_mismatch')
        snapshot_selected(source, export, 'candidate-source', pins['candidateFiles'])
        pre_format = snapshot_tree(source, entries, pins['symlinks'])
        check_scope(compare_snapshots(base_tree, pre_format, pins['allowedChangedFiles']), pins['allowedChangedFiles'])
        write(export / 'pre-format-tree.json', pre_format)
        (export / 'candidate.patch').write_bytes(git('diff', '--no-ext-diff', '--no-textconv', '--full-index', '--binary'))
        prefix = root / 'tools'
        binaries = prefix / 'bin'
        binaries.mkdir(parents=True)
        downloads = root / 'downloads'
        downloads.mkdir()
        env['PATH'] = str(binaries) + ':/usr/bin:/bin'
        env['RUSTC'] = str(binaries / 'rustc')
        env['RUSTDOC'] = str(binaries / 'rustdoc')
        for number, tool in enumerate(tools['downloads']):
            need(tool['url'].startswith('https://') and tool.get('bytes') and tool['bytes'] < 256 * 1024**2, 'invalid_tool_download_pin')
            archive = downloads / str(number)
            count = 0
            with urllib.request.urlopen(tool['url'], timeout=60) as response, archive.open('xb') as handle:
                while chunk := response.read(1024**2):
                    count += len(chunk)
                    need(count <= tool['bytes'], 'tool_download_size_exceeded')
                    handle.write(chunk)
            need(count == tool['bytes'] and digest(archive) == tool['sha256'], 'tool_download_digest_mismatch')
            result['downloads'].append({'name': tool['name'], 'version': tool['version'], 'url': tool['url'], 'sha256': digest(archive), 'bytes': count})
            write(export / 'download-receipts.json', result['downloads'])
            extracted = root / ('unpack-' + str(number))
            safe_extract(archive, extracted)
            if tool['kind'] == 'rust-component':
                component = extracted / tool['root']
                need(regular(component / 'install.sh') and regular(component / 'components'), 'rust_installer_layout')
                need((component / 'components').read_text().strip() == tool['component_file_must_equal'], 'rust_component_mismatch')
                run(['sh', str(component / 'install.sh'), '--prefix=' + str(prefix), '--disable-ldconfig'], 'install-' + tool['name'], timeout=120, cwd=component)
            else:
                need(tool['kind'] == 'tar', 'unknown_tool_archive_kind')
                matches = [p for p in extracted.rglob(tool['member']) if p.name == tool['member'] and regular(p)]
                need(len(matches) == 1, 'tool_archive_member_ambiguity')
                target = binaries / tool['executable']
                shutil.copyfile(matches[0], target)
                target.chmod(0o755)
        versions = {}
        for name, prefix_text in {'cargo-nextest': 'cargo-nextest 0.9.146 ', 'rustc': 'rustc 1.99.1 ', 'cargo': 'cargo 1.99.1 ', 'rustfmt': 'rustfmt 1.10.0-', 'just': 'just 1.58.0', 'uv': 'uv 0.11.3 ', 'dotslash': 'DotSlash 0.5.9'}.items():
            path = binaries / name
            need(regular(path), 'installed_tool_not_regular')
            version = run([str(path), '--version'], 'version-' + name, capture=True).decode().strip()
            need(version.startswith(prefix_text) or (name == 'rustfmt' and version == prefix_text.removesuffix('-')), 'installed_version_mismatch_' + name)
            versions[name] = {'version': version, 'sha256': digest(path)}
        for name in ('python3', 'git', 'bash'):
            path = Path(shutil.which(name, path=env['PATH']))
            version = run([str(path), '--version'], 'version-' + name, capture=True).decode().splitlines()[0]
            versions[name] = {'version': version, 'sha256': digest(path)}
        # System prerequisites are supplied by the named public runner image.
        # Hash the actual files; no apt/sudo/system mutation or personal config.
        for name in ('cc', 'c++', 'ar', 'ld', 'make', 'cmake', 'pkg-config', 'clang', 'readelf', 'zstd'):
            found = shutil.which(name, path='/usr/bin:/bin')
            need(found is not None, 'missing_system_tool_' + name.replace('+', 'p').replace('-', '_'))
            path = Path(found).resolve(strict=True)
            need(regular(path), 'system_tool_not_regular')
            version = run([str(path), '--version'], 'version-system-' + name.replace('+', 'p'), capture=True).decode(errors='replace').splitlines()[0]
            versions[name] = {'version': version, 'path': str(path), 'sha256': digest(path)}
        need(regular(Path('/sbin/ldconfig').resolve(strict=True)), 'missing_ldconfig')
        versions['ldconfig'] = {'path': str(Path('/sbin/ldconfig').resolve()), 'sha256': digest(Path('/sbin/ldconfig'))}
        write(export / 'tool-identity.json', versions)
        lock_rows = validate_lock(source / 'codex-rs/Cargo.lock')
        write(export / 'cargo-lock-provenance.json', {'lockSha256': digest(source / 'codex-rs/Cargo.lock'), 'sources': lock_rows})
        env['CARGO_NET_OFFLINE'] = 'false'
        run(['cargo', 'fetch', '--locked'], 'public-locked-fetch', timeout=900, cwd=source / 'codex-rs')
        env['CARGO_NET_OFFLINE'] = 'true'
        write(export / 'cargo-cache-inventory.json', cargo_cache_inventory(root / 'cargo-home', lock_rows))
        closure = run(['cargo', 'tree', '--locked', '--offline', '-p', PACKAGE, '--edges', 'normal,build,dev', '--prefix', 'none'], 'offline-closure', timeout=120, capture=True, cwd=source / 'codex-rs')
        write(export / 'closure.json', check_closure(closure))
        write(export / 'metadata-before-compile.json', metadata_inventory(root / 'metadata-target'))
        resource = fresh_target(root / 'generation-target', shutil.disk_usage(root).free)
        write(export / 'resource-admission.json', resource)
        env['CARGO_TARGET_DIR'] = str(root / 'generation-target')
        result['nativeCounts']['compileInvocations'] += 1
        compile_failure = None
        try:
            run(compile_command(), 'ordinary-zero-selection-compile', timeout=3150)
            result['nativeCounts']['compileSucceeded'] = 1
        except BaseException as error:
            compile_failure = error
        try:
            result['compileJUnit'] = retain_junit(source, export, 'compile')
            result['compileRuntimeStore'] = runtime_store_inventory(source, require_junit=True)
        except BaseException as error:
            result['compileJUnitFailure'] = failure_code(error)
            if compile_failure is None:
                compile_failure = error
        if compile_failure is not None:
            raise compile_failure
        compile_tree = snapshot_tree(source, entries, pins['symlinks'])
        write(export / 'compile-tree.json', compile_tree)
        need(not compare_snapshots(pre_format, compile_tree, []), 'source_changed_during_compile')
        binary = capture_binary(root / 'generation-target', export, run)
        result['generatorBinary'] = binary
        # Remove only the already retained known XML before the second run;
        # a stale compile-only report cannot satisfy the generator oracle.
        (source / 'codex-rs/target/nextest/local/junit.xml').unlink()
        env['CODEX_APP_SERVER_SCHEMA_ROOT'] = str(source / 'codex-rs/app-server-protocol/schema')
        env['CODEX_APP_SERVER_SCHEMA_EXPERIMENTAL'] = '0'
        need('CODEX_APP_SERVER_SCHEMA_PRETTIER' not in env, 'unexpected_prettier_override')
        result['nativeCounts']['generatorInvocations'] += 1
        generator_failure = None
        try:
            run(generator_command(), 'ordinary-stable-schema-generator', timeout=300)
        except BaseException as error:
            generator_failure = error
        try:
            result['generatorJUnit'] = retain_junit(source, export)
            result['generatorRuntimeStore'] = runtime_store_inventory(source, require_junit=True)
        except BaseException as error:
            result['generatorJUnitFailure'] = failure_code(error)
            if generator_failure is None:
                generator_failure = error
        if generator_failure is not None:
            raise generator_failure
        log_name = next(row['log'] for row in result['phases'] if row['phase'] == 'ordinary-stable-schema-generator')
        result['generatorOracle'] = validate_generator((export / 'generator-junit.xml').read_bytes(), (export / log_name).read_bytes())
        result['nativeCounts']['generatorBodiesVerified'] = 1
        result['generatorBinaryAfterSha256'] = digest(root / 'generation-target' / binary['targetRelativePath'])
        need(result['generatorBinaryAfterSha256'] == binary['executableSha256'], 'generator_binary_changed')
        result['schemaGenerated'] = snapshot_schema(source, export, 'schema-generated', pins)
        generation_tree = snapshot_tree(source, entries, pins['symlinks'])
        write(export / 'generation-tree.json', generation_tree)
        result['generatorChangedFiles'] = compare_snapshots(pre_format, generation_tree, schema_paths(pins))
        need(STABLE in result['generatorChangedFiles'], 'stable_schema_unchanged')
        write(export / 'generation-delta.json', {'changedFiles': result['generatorChangedFiles'], 'semanticReviewRequired': True})
        result['decodedBefore'] = decode_stable(export / 'schema-before' / STABLE, export / 'baseline-stable-decoded.json', run, 'decode-baseline-stable')
        result['decodedGenerated'] = decode_stable(export / 'schema-generated' / STABLE, export / 'generated-stable-decoded.json', run, 'decode-generated-stable')
        (export / 'generated-schema.patch').write_bytes(git('diff', '--no-ext-diff', '--no-textconv', '--full-index', '--binary', '--', 'codex-rs/app-server-protocol/schema'))
        env['CARGO_TARGET_DIR'] = str(root / 'metadata-target')
        del env['CODEX_APP_SERVER_SCHEMA_ROOT']
        del env['CODEX_APP_SERVER_SCHEMA_EXPERIMENTAL']
        run(['just', 'fmt'], 'full-fmt', timeout=600)
        result['fullFormatterExitCode'] = 0
        result['candidateAfterFormat'] = selected_hashes()
        snapshot_selected(source, export, 'formatted-source', selected_final)
        result['schemaFinal'] = snapshot_schema(source, export, 'schema-final', pins)
        result['decodedFinal'] = decode_stable(export / 'schema-final' / STABLE, export / 'final-stable-decoded.json', run, 'decode-final-stable')
        post_format = snapshot_tree(source, entries, pins['symlinks'])
        write(export / 'post-format-tree.json', post_format)
        result['formatterChangedFiles'] = compare_snapshots(generation_tree, post_format, pins['allowedChangedFiles'])
        result['changedFiles'] = git('diff', '--name-only').decode().splitlines()
        check_scope(result['changedFiles'], allowed_final)
        git('diff', '--check')
        need(not git('ls-files', '--others', '--exclude-standard'), 'unexpected_untracked_subject_files')
        result['finalRuntimeStore'] = runtime_store_inventory(source, require_junit=True)
        write(export / 'native-target-inventory.json', usage(root / 'generation-target'))
        (export / 'formatted.patch').write_bytes(git('diff', '--no-ext-diff', '--no-textconv', '--full-index', '--binary'))
        import difflib
        delta = []
        for name in pins['candidateFiles']:
            before = (export / 'candidate-source' / name).read_text().splitlines(keepends=True)
            after = (export / 'formatted-source' / name).read_text().splitlines(keepends=True)
            delta.extend(difflib.unified_diff(before, after, fromfile='a/' + name, tofile='b/' + name))
        (export / 'formatter-delta.patch').write_text(''.join(delta))
        result['symlinksAfter'] = link_records(source, tree, pins['symlinks'])
        inventory = metadata_inventory(root / 'metadata-target')
        write(export / 'metadata-target.json', inventory)
        result['metadataTargetInventorySha256'] = digest(export / 'metadata-target.json')
        result['formattedPatchSha256'] = digest(export / 'formatted.patch')
        result['formatterDeltaSha256'] = digest(export / 'formatter-delta.patch')
        result['sourceNeedsReviewOfFormatterDelta'] = bool(result['formatterChangedFiles'])
        write(export / 'source-delta.json', {'formatterChangedFiles': result['formatterChangedFiles'], 'candidateBefore': result['candidateBefore'], 'candidateAfterFormat': result['candidateAfterFormat']})
        result['completed'] = True
        result['disposition'] = 'One canonical stable-schema generator body through ordinary just test and full just fmt completed. Generated artifacts require root semantic validation and source review. No protocol, state, core, app-server integration, TUI or Windows regression bodies were selected; productQualified remains false.'
    except BaseException as error:
        result['failureCode'] = failure_code(error)
    finally:
        try:
            need(not result.get('processTimeout'), 'snapshot_deferred_until_controller_cleanup')
            result['finalSourceSnapshot'] = snapshot_selected(source, export, 'final-source', selected_final)
            if entries is not None:
                final_tree = snapshot_tree(source, entries, pins['symlinks'])
                write(export / 'final-tree.json', final_tree)
                if pre_format is not None:
                    compare_snapshots(pre_format, final_tree, allowed_final)
        except BaseException as error:
            result['snapshotFailure'] = failure_code(error)
            result['completed'] = False
        write(export / 'worker-result.json', result)
    return 0 if result['completed'] else 1


if __name__ == '__main__':
    sys.exit(main(Path(sys.argv[1]), Path(sys.argv[2])))
