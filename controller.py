#!/usr/bin/env python3
"""One admitted disposable-host full formatter; never product qualification."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
BRANCH = 'codex/pr1210-fullfmt-v1-20261021'
WORKFLOW = '.github/workflows/pr1210-fullfmt-v1.yml'
GIB = 1024**3
WORK_SECONDS = 1500
MAX_LOG_BYTES = 64 * 1024**2
MAX_EVIDENCE_BYTES = 128 * 1024**2


def need(condition, code):
    if not condition:
        raise RuntimeError(code)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024**2), b''):
            h.update(chunk)
    return h.hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def failure_code(error):
    value = str(error)
    return value if isinstance(error, RuntimeError) and re.fullmatch('[a-z0-9_]+', value) else type(error).__name__


def safe_path(root, relative):
    name = Path(relative)
    need(not name.is_absolute() and name.parts and '..' not in name.parts, 'relative_path_escape')
    current = root
    need(stat.S_ISDIR(current.lstat().st_mode), 'root_not_directory')
    for part in name.parts[:-1]:
        current = current / part
        need(stat.S_ISDIR(current.lstat().st_mode), 'parent_not_directory')
    return root / name


def admitted(packet, admission, manifest):
    need(admission.get('approved') is True, 'method_not_admitted')
    need(re.fullmatch('[a-f0-9]{64}', admission.get('reviewReceiptSha256') or ''), 'missing_review_binding')
    need(admission.get('packetManifestSha256') == digest(packet / 'packet-manifest.json'), 'admitted_manifest_mismatch')
    names = [row['path'] for row in manifest['files']]
    need(len(names) == len(set(names)) and names, 'duplicate_or_empty_manifest')
    for row in manifest['files']:
        path = safe_path(packet, row['path'])
        need(stat.S_ISREG(path.lstat().st_mode), 'packet_file_type')
        need(path.stat().st_size == row['bytes'] and digest(path) == row['sha256'], 'packet_hash_mismatch')


def identity_check(env):
    keys = ['GITHUB_ACTIONS', 'GITHUB_REPOSITORY', 'GITHUB_EVENT_NAME', 'GITHUB_REF', 'GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_RUN_NUMBER', 'GITHUB_WORKFLOW_REF', 'ImageOS', 'ImageVersion']
    identity = {key: env.get(key) for key in keys}
    need(identity['GITHUB_ACTIONS'] == 'true' and identity['GITHUB_REPOSITORY'] == 'citadelculture/CorbanuTerminal', 'wrong_host_or_repository')
    need(identity['GITHUB_EVENT_NAME'] == 'push' and identity['GITHUB_REF'] == 'refs/heads/' + BRANCH, 'wrong_workflow_route')
    need(identity['GITHUB_RUN_ATTEMPT'] == '1' and identity['GITHUB_RUN_NUMBER'] == '1', 'not_first_one_shot_run')
    need(identity['GITHUB_WORKFLOW_REF'] == identity['GITHUB_REPOSITORY'] + '/' + WORKFLOW + '@refs/heads/' + BRANCH, 'wrong_workflow_identity')
    need(re.fullmatch('[0-9]+', identity['GITHUB_RUN_ID'] or '') and re.fullmatch('[a-f0-9]{40}', identity['GITHUB_SHA'] or ''), 'missing_run_identity')
    need(identity['ImageOS'] == 'ubuntu24' and re.fullmatch('[A-Za-z0-9._-]+', identity['ImageVersion'] or ''), 'wrong_image_identity')
    return identity


def child_environment(parent, root):
    home, scratch = root / 'home', root / 'tmp'
    home.mkdir(mode=0o700)
    scratch.mkdir(mode=0o700)
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1', 'HOME': str(home), 'TMPDIR': str(scratch), 'TMP': str(scratch), 'TEMP': str(scratch)}
    env.update({k: v for k, v in parent.items() if k.startswith('CODEX_SANDBOX')})
    need(all((k in env and env[k] == v) for k, v in parent.items() if k.startswith('CODEX_SANDBOX')), 'sandbox_control_changed')
    return env


def group_state(pid):
    try:
        os.killpg(pid, 0)
        return 'present'
    except ProcessLookupError:
        return 'absent'
    except PermissionError:
        return 'unknown'


def cleanup(child):
    result = {'directChildReaped': False, 'ownedGroupGone': False, 'signals': []}
    for sig, grace in [(signal.SIGTERM, 10), (signal.SIGKILL, 5)]:
        state = group_state(child.pid)
        if state == 'unknown':
            result['failure'] = 'owned_group_state_unknown'
            break
        if state == 'absent':
            break
        try:
            os.killpg(child.pid, sig)
            result['signals'].append(sig.name)
        except ProcessLookupError:
            pass
        limit = time.monotonic() + grace
        while group_state(child.pid) == 'present' and time.monotonic() < limit:
            child.poll()
            time.sleep(0.2)
    try:
        child.wait(timeout=5)
        result['directChildReaped'] = True
    except subprocess.TimeoutExpired:
        result['failure'] = 'direct_child_not_reaped'
    result['ownedGroupGone'] = group_state(child.pid) == 'absent'
    return result


def complete(worker, result):
    return bool(worker.get('completed') and result.get('workerExitCode') == 0 and not result.get('failureCode') and result.get('cleanup', {}).get('ownedGroupGone') and result.get('cleanup', {}).get('directChildReaped') and not result.get('snapshotFailure') and result.get('ownedStateRemoved') is True)


def remove_owned_state(root, progress, expected_identity, *, seconds=60, max_entries=100000):
    """Remove only the known owned tree; never chmod files or follow symlinks."""
    need(re.fullmatch(r"pr1210-format-[0-9]+", root.name), "owned_cleanup_root_name")
    deadline = time.monotonic() + seconds
    uid = os.geteuid()
    progress.update(entries=0, directoriesRepaired=0, repairedDirectorySample=[],
                    activeRelativePath='.', completed=False, deadlineSeconds=seconds,
                    entryLimit=max_entries, filePermissionsChanged=0, symlinksFollowed=0)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

    def bounded(relative):
        progress['activeRelativePath'] = relative
        need(time.monotonic() < deadline, 'owned_cleanup_deadline')
        need(progress['entries'] < max_entries, 'owned_cleanup_entry_bound')
        progress['entries'] += 1

    def walk(fd, relative, depth):
        need(depth <= 64, 'owned_cleanup_depth_bound')
        st = os.fstat(fd)
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == uid, 'owned_cleanup_foreign_directory')
        desired = stat.S_IMODE(st.st_mode) | stat.S_IRWXU
        if desired != stat.S_IMODE(st.st_mode):
            os.fchmod(fd, desired)
            progress['directoriesRepaired'] += 1
            if len(progress['repairedDirectorySample']) < 128:
                progress['repairedDirectorySample'].append({'path': relative, 'beforeMode': oct(stat.S_IMODE(st.st_mode)), 'afterMode': oct(desired)})
        for name in os.listdir(fd):
            child = name if relative == '.' else relative + '/' + name
            bounded(child)
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(before.st_mode):
                child_fd = os.open(name, flags, dir_fd=fd)
                try:
                    actual = os.fstat(child_fd)
                    need((actual.st_dev, actual.st_ino) == (before.st_dev, before.st_ino), 'owned_cleanup_directory_changed')
                    walk(child_fd, child, depth + 1)
                finally:
                    os.close(child_fd)
                os.rmdir(name, dir_fd=fd)
            else:
                need(stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode), 'owned_cleanup_special_entry')
                os.unlink(name, dir_fd=fd)

    bounded('.')
    # Root's parent/name identity is checked before the final unlink. All
    # descendant operations are relative to already opened no-follow dir fds.
    parent_fd = os.open(root.parent, flags)
    try:
        root_fd = os.open(root.name, flags, dir_fd=parent_fd)
        try:
            original = os.fstat(root_fd)
            need((original.st_dev, original.st_ino) == tuple(expected_identity), "owned_cleanup_root_identity")
            walk(root_fd, '.', 0)
        finally:
            os.close(root_fd)
        current = os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
        need(stat.S_ISDIR(current.st_mode) and (current.st_dev, current.st_ino) == (original.st_dev, original.st_ino), 'owned_cleanup_root_changed')
        need(time.monotonic() < deadline, 'owned_cleanup_deadline')
        os.rmdir(root.name, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    progress.update(completed=True, activeRelativePath=None)


def main():
    raw = HERE.parent / 'pr1210-format-raw'
    public = HERE.parent / 'pr1210-format-evidence'
    raw.mkdir(exist_ok=False)
    public.mkdir(exist_ok=False)
    result = {'schema': 'pr1210-format-controller-v1', 'completed': False, 'productQualified': False, 'failureCode': None, 'nativeProductBuilds': 0, 'nativeProductTests': 0}
    child, root, pins, worker_data = None, None, None, {}
    try:
        admitted(HERE, json.loads((HERE / 'admission.json').read_text()), json.loads((HERE / 'packet-manifest.json').read_text()))
        identity = identity_check(os.environ)
        result['identity'] = identity
        need(sys.platform == 'linux' and os.uname().machine == 'x86_64' and os.getuid() != 0 and os.geteuid() != 0, 'wrong_platform_or_root')
        need(subprocess.check_output(['git', '-C', str(HERE), 'rev-parse', 'HEAD'], timeout=10).decode().strip() == identity['GITHUB_SHA'], 'method_checkout_head_mismatch')
        result.update(packetManifestSha256=digest(HERE / 'packet-manifest.json'), admissionSha256=digest(HERE / 'admission.json'))
        pins = json.loads((HERE / 'source-pins.json').read_text())
        temp = Path(os.environ['RUNNER_TEMP'])
        need(stat.S_ISDIR(temp.lstat().st_mode), 'runner_temp_not_directory')
        root = temp / ('pr1210-format-' + identity['GITHUB_RUN_ID'])
        root.mkdir(mode=0o700, exist_ok=False)
        created = root.lstat()
        result['ownedRootIdentity'] = [created.st_dev, created.st_ino]
        free = shutil.disk_usage(root).free
        need(free >= 8 * GIB, 'disposable_admission_below_8GiB')
        result['resources'] = {'freeBeforeBytes': free, 'admissionBytes': 8 * GIB, 'continuousFloorBytes': 2 * GIB, 'workSeconds': WORK_SECONDS, 'cleanupAndExportReserveSeconds': 300, 'ownerHostPolicyChanged': False}
        env = child_environment(os.environ, root)
        result['inheritedSandboxGuardsPreserved'] = True
        with (raw / 'controller-raw.log').open('wb') as log:
            child = subprocess.Popen([sys.executable, str(HERE / 'worker.py'), str(root), str(raw)], env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            result['ownedProcessGroup'] = child.pid
            deadline = time.monotonic() + WORK_SECONDS
            while child.poll() is None:
                files = [p for p in raw.rglob('*') if stat.S_ISREG(p.lstat().st_mode)]
                total = sum(p.stat().st_size for p in files)
                logs = sum(p.stat().st_size for p in files if p.suffix == '.log')
                if time.monotonic() >= deadline:
                    result['failureCode'] = 'global_deadline'
                elif shutil.disk_usage(root).free < 2 * GIB:
                    result['failureCode'] = 'continuous_space_floor'
                elif logs > MAX_LOG_BYTES or total > MAX_EVIDENCE_BYTES:
                    result['failureCode'] = 'evidence_size_bound'
                if result['failureCode']:
                    break
                time.sleep(1)
    except BaseException as error:
        result['failureCode'] = result['failureCode'] or failure_code(error)
    finally:
        if child is not None:
            try:
                result['cleanup'] = cleanup(child)
                result['workerExitCode'] = child.returncode
            except BaseException as error:
                result['cleanup'] = {'failure': failure_code(error), 'ownedGroupGone': False, 'directChildReaped': False}
        try:
            path = raw / 'worker-result.json'
            if path.exists() and stat.S_ISREG(path.lstat().st_mode):
                need(path.stat().st_size <= 2 * 1024**2, 'worker_result_size')
                worker_data = json.loads(path.read_text())
                result['workerResultSha256'] = digest(path)
                result['workerFailureCode'] = worker_data.get('failureCode')
            elif child is not None:
                result['failureCode'] = result['failureCode'] or 'worker_result_missing'
        except BaseException as error:
            result['failureCode'] = result['failureCode'] or 'worker_result_' + failure_code(error)
        # Only the known public source files are copied, and only after owned
        # processes are gone. Never dereference the tracked external fixture.
        if child is not None and result.get('cleanup', {}).get('ownedGroupGone'):
            try:
                from worker import snapshot_selected, snapshot_tree, tree_entries
                subject = HERE.parent / 'subject'
                result['controllerFinalSnapshot'] = snapshot_selected(subject, raw, 'controller-final', pins['candidateFiles'])
                tree = subprocess.check_output(['git', '-C', str(subject), 'ls-tree', '-r', '-z', '--full-tree', 'HEAD'], timeout=30)
                need(hashlib.sha256(tree).hexdigest() == pins['baseGitLsTreeSha256'], 'final_git_tree_changed')
                final_tree = snapshot_tree(subject, tree_entries(tree), pins['symlinks'])
                write(raw / 'controller-final-tree.json', final_tree)
                if worker_data.get('completed'):
                    need(final_tree == json.loads((raw / 'post-format-tree.json').read_text()), 'source_changed_after_worker_snapshot')
            except BaseException as error:
                result['snapshotFailure'] = failure_code(error)
        if root is not None:
            try:
                result['freeAfterBytes'] = shutil.disk_usage(root).free
                if child is None or (result.get('cleanup', {}).get('ownedGroupGone') and result.get('cleanup', {}).get('directChildReaped')):
                    result['stateCleanup'] = {}
                    remove_owned_state(root, result['stateCleanup'], result['ownedRootIdentity'])
                    result['ownedStateRemoved'] = not root.exists()
                else:
                    result['ownedStateRemoved'] = False
            except BaseException as error:
                result['ownedStateRemoved'] = False
                result['stateCleanupFailure'] = failure_code(error)
        result['completed'] = complete(worker_data, result)
        try:
            from evidence import export_audited
            export_audited(raw, public, result, (pins or {}).get('candidateFiles', {}))
        except BaseException as error:
            result['completed'] = False
            result['exportFailure'] = failure_code(error)
            write(public / 'controller-result.json', result)
    return 0 if result['completed'] else 1


if __name__ == '__main__':
    sys.exit(main())
