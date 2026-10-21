#!/usr/bin/env python3
"""Exact public source full formatting only; no native builds/tests."""
import hashlib
import json
import os
import re
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


def require_absent(source, relative):
    name = Path(relative)
    need(not name.is_absolute() and name.parts and '..' not in name.parts, 'added_path_escape')
    current = source
    need(stat.S_ISDIR(current.lstat().st_mode), 'subject_root_not_directory')
    for number, part in enumerate(name.parts):
        current /= part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            return
        need(number < len(name.parts) - 1, 'added_path_preexists')
        need(stat.S_ISDIR(mode), 'added_parent_not_directory')


def snapshot_selected(source, export, label, candidate_files, absent_files=()):
    records = {}
    need(set(absent_files) <= set(candidate_files) and (not absent_files or label == 'base-source'), 'invalid_absent_source_scope')
    for name in candidate_files:
        if name in absent_files:
            require_absent(source, name)
            records[name] = {'type': 'absent', 'reason': 'explicit_added_regular_file'}
            continue
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


def expanded_entries(base_entries, pins):
    additions = pins.get('addedRegularFiles', {})
    base_names = {x['path'] for x in base_entries}
    need(not (base_names & set(additions)), 'added_path_in_base_tree')
    need(set(additions) <= set(pins['candidateFiles']) <= set(pins['allowedChangedFiles']), 'added_pin_scope')
    rows = list(base_entries)
    for name, pin in additions.items():
        path = PurePosixPath(name)
        need(not path.is_absolute() and path.parts and '..' not in path.parts and str(path) == name, 'added_path_escape')
        need(pin['mode'] == '100644' and re.fullmatch('[a-f0-9]{40}', pin['blob']) and re.fullmatch('[a-f0-9]{64}', pin['sha256']), 'added_pin_invalid')
        need(pin['sha256'] == pins['candidateFiles'][name] and isinstance(pin['bytes'], int) and 0 <= pin['bytes'] <= 2 * 1024**2, 'added_pin_mismatch')
        need(not any(str(parent) in base_names or str(parent) in additions for parent in path.parents if str(parent) != '.'), 'added_parent_file_conflict')
        rows.append({'path': name, 'mode': pin['mode'], 'blob': pin['blob']})
    need(len(rows) <= 60000, 'tree_entry_bound_or_duplicate')
    return sorted(rows, key=lambda x: x['path'])


def verify_index_inventory(raw, base_entries, additions):
    expected = {row['path']: (row['mode'], row['blob']) for row in base_entries}
    empty_blob = hashlib.sha1(b'blob 0\0').hexdigest()
    for name, pin in additions.items():
        need(name not in expected, 'added_path_in_base_tree')
        expected[name] = (pin['mode'], empty_blob)
    actual = {}
    for record in raw.split(b'\0'):
        if not record:
            continue
        metadata, name = record.split(b'\t', 1)
        mode, blob, stage = metadata.decode().split()
        path = os.fsdecode(name)
        need(stage == '0' and path not in actual, 'index_conflict_or_duplicate')
        actual[path] = (mode, blob)
    need(actual == expected, 'post_patch_index_inventory_changed')


def compare_candidate_snapshots(before, after, allowed, additions):
    need(set(after) - set(before) == set(additions) and not (set(before) - set(after)), 'candidate_inventory_changed')
    changed = compare_snapshots(before, {name: after[name] for name in before}, allowed)
    for name, pin in additions.items():
        need(after[name] == {'type': 'regular', 'mode': pin['mode'], 'bytes': pin['bytes'], 'sha256': pin['sha256']}, 'added_file_identity_mismatch')
    changed.extend(additions)
    check_scope(changed, allowed)
    return sorted(changed)


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
    if root.exists():
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
    result = {'schema': 'pr951-format-worker-v1', 'completed': False, 'failureCode': None, 'productQualified': False, 'nativeProductBuilds': 0, 'nativeProductTests': 0, 'base': pins['base'], 'phases': [], 'downloads': []}
    env = os.environ.copy()
    env.update({'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0', 'GIT_ASKPASS': '/usr/bin/false', 'GIT_NO_LAZY_FETCH': '1', 'CARGO_HOME': str(root / 'cargo-home'), 'CARGO_TARGET_DIR': str(root / 'metadata-target'), 'CARGO_NET_OFFLINE': 'true', 'UV_CACHE_DIR': str(root / 'cache/uv'), 'XDG_CACHE_HOME': str(root / 'cache/xdg'), 'UV_PYTHON': sys.executable, 'UV_PYTHON_DOWNLOADS': 'never'})
    need(not any(key in env for key in ('GITHUB_TOKEN', 'GH_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'BUILDBUDDY_API_KEY')), 'unexpected_credential_environment')
    command_number = 0
    entries = None
    base_entries = None
    pre_format = None

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
        base_entries = tree_entries(tree)
        expected_entries = expanded_entries(base_entries, pins)
        additions = pins.get('addedRegularFiles', {})
        entries = base_entries
        result['symlinksBefore'] = link_records(source, tree, pins['symlinks'])
        write(export / 'source-layout.json', {'baseTree': pins['baseTree'], 'gitTreeSha256': hashlib.sha256(tree).hexdigest(), 'entries': len(entries), 'symlinks': result['symlinksBefore']})
        for name, expected in pins['baseFiles'].items():
            path = subject_path(source, name)
            need(regular(path) and digest(path) == expected, 'baseline_source_hash_mismatch')
        base_tree = snapshot_tree(source, entries, pins['symlinks'])
        write(export / 'base-tree.json', base_tree)
        snapshot_selected(source, export, 'base-source', pins['candidateFiles'], additions)
        need(digest(HERE / 'subject.patch') == pins['patchSha256'], 'patch_hash_mismatch')
        git('apply', '--check', str(HERE / 'subject.patch'))
        if additions:
            git('apply', str(HERE / 'subject.patch'))
            untracked = git('ls-files', '--others', '--exclude-standard', '-z')
            need(set(os.fsdecode(x) for x in untracked.split(b'\0') if x) == set(additions), 'unexpected_added_subject_files')
            git('add', '--intent-to-add', '--', *sorted(additions))
            verify_index_inventory(git('ls-files', '--stage', '-z'), base_entries, additions)
            need(not git('ls-files', '--others', '--exclude-standard', '-z'), 'unexpected_untracked_subject_files')
        else:
            git('apply', str(HERE / 'subject.patch'))
        entries = expected_entries
        result['candidateBefore'] = selected_hashes()
        need(result['candidateBefore'] == pins['candidateFiles'], 'candidate_source_hash_mismatch')
        snapshot_selected(source, export, 'candidate-source', pins['candidateFiles'])
        pre_format = snapshot_tree(source, entries, pins['symlinks'])
        check_scope(compare_candidate_snapshots(base_tree, pre_format, pins['allowedChangedFiles'], additions), pins['allowedChangedFiles'])
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
        for name, prefix_text in {'rustc': 'rustc 1.99.1 ', 'cargo': 'cargo 1.99.1 ', 'rustfmt': 'rustfmt 1.10.0-', 'just': 'just 1.58.0', 'uv': 'uv 0.11.3 ', 'dotslash': 'DotSlash 0.5.9'}.items():
            path = binaries / name
            need(regular(path), 'installed_tool_not_regular')
            version = run([str(path), '--version'], 'version-' + name, capture=True).decode().strip()
            need(version.startswith(prefix_text) or (name == 'rustfmt' and version == prefix_text.removesuffix('-')), 'installed_version_mismatch_' + name)
            versions[name] = {'version': version, 'sha256': digest(path)}
        for name in ('python3', 'git', 'bash'):
            path = Path(shutil.which(name, path=env['PATH']))
            version = run([str(path), '--version'], 'version-' + name, capture=True).decode().splitlines()[0]
            versions[name] = {'version': version, 'sha256': digest(path)}
        write(export / 'tool-identity.json', versions)
        run(['just', 'fmt'], 'full-fmt', timeout=600)
        result['fullFormatterExitCode'] = 0
        result['candidateAfterFormat'] = selected_hashes()
        snapshot_selected(source, export, 'formatted-source', pins['candidateFiles'])
        post_format = snapshot_tree(source, entries, pins['symlinks'])
        write(export / 'post-format-tree.json', post_format)
        result['formatterChangedFiles'] = compare_snapshots(pre_format, post_format, pins['allowedChangedFiles'])
        result['changedFiles'] = git('diff', '--name-only').decode().splitlines()
        check_scope(result['changedFiles'], pins['allowedChangedFiles'])
        git('diff', '--check')
        if additions:
            verify_index_inventory(git('ls-files', '--stage', '-z'), base_entries, additions)
        need(not git('ls-files', '--others', '--exclude-standard'), 'unexpected_untracked_subject_files')
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
        result['disposition'] = 'Full ordinary formatting completed within the exact pinned source scope. Root must adopt exact formatted bytes and inspect any formatter delta. No native product build, test, Windows body or functional qualification.'
    except BaseException as error:
        result['failureCode'] = failure_code(error)
    finally:
        try:
            result['finalSourceSnapshot'] = snapshot_selected(source, export, 'final-source', pins['candidateFiles'])
            if entries is not None:
                final_tree = snapshot_tree(source, entries, pins['symlinks'])
                write(export / 'final-tree.json', final_tree)
                if pre_format is not None:
                    compare_snapshots(pre_format, final_tree, pins['allowedChangedFiles'])
        except BaseException as error:
            result['snapshotFailure'] = failure_code(error)
            result['completed'] = False
        write(export / 'worker-result.json', result)
    return 0 if result['completed'] else 1


if __name__ == '__main__':
    sys.exit(main(Path(sys.argv[1]), Path(sys.argv[2])))
