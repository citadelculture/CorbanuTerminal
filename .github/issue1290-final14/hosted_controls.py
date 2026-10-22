"""Source, process and evidence controls shared by the hosted driver and tests."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_json(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def group_absent(pid):
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def reap_owned(child):
    result = {'pid': child.pid, 'reaped': False, 'processGroupAbsent': False, 'errors': []}
    try:
        if child.poll() is None or not group_absent(child.pid):
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            child.wait(timeout=15)
    except (OSError, subprocess.SubprocessError) as error:
        result['errors'].append(str(error))
    try:
        if child.poll() is None or not group_absent(child.pid):
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        child.wait(timeout=15)
        result['reaped'] = True
        result['exitCode'] = child.returncode
    except (OSError, subprocess.SubprocessError) as error:
        result['errors'].append(str(error))
    deadline = time.monotonic() + 3
    while not group_absent(child.pid) and time.monotonic() < deadline:
        time.sleep(0.1)
    result['processGroupAbsent'] = group_absent(child.pid)
    return result


def run_bounded(label, argv, seconds, evidence, records, available, reserve,
                stop_container=None, allow_failure=False, poll_seconds=2):
    record = {'label': label, 'argv': argv, 'startedAt': now(), 'timeoutSeconds': seconds,
              'spawned': False, 'reaped': False, 'processGroupAbsent': False, 'errors': []}
    records.append(record)
    child = None
    cause = None
    try:
        if available() < reserve:
            raise RuntimeError('prelaunch continuous disk reserve')
        with (evidence / (label + '.log')).open('xb') as log, (evidence / (label + '-resources.jsonl')).open('x') as samples:
            child = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            record['spawned'] = True
            start = time.monotonic()
            while child.poll() is None:
                free = available()
                samples.write(json.dumps({'at': now(), 'usableBytes': free}) + '\n')
                samples.flush()
                if free < reserve:
                    raise RuntimeError('continuous disk reserve')
                if time.monotonic() - start > seconds:
                    raise TimeoutError('stage deadline')
                time.sleep(poll_seconds)
            child.wait(timeout=15)
            if child.returncode and not allow_failure:
                raise RuntimeError('command exit ' + str(child.returncode))
    except BaseException as error:
        cause = error
        record['errors'].append(type(error).__name__ + ': ' + str(error))
    finally:
        # Container failure must never prevent local client termination/reaping.
        if cause and stop_container:
            try:
                stop_container()
            except BaseException as error:
                record['errors'].append('container cleanup: ' + str(error))
        if child is not None:
            try:
                reaped = reap_owned(child)
                record['errors'].extend(reaped.pop('errors'))
                record.update(reaped)
            except BaseException as error:
                record['errors'].append('client cleanup: ' + str(error))
        record['endedAt'] = now()
        write_json(evidence / (label + '-result.json'), record)
    if cause or (child is not None and not (record['reaped'] and record['processGroupAbsent'])):
        raise RuntimeError('Stage failed or client cleanup unknown: ' + label) from cause
    return child.returncode


def source_state(source, pin, expected_hashes, allowed_untracked, evidence, label):
    def git(*args):
        return subprocess.check_output(['git', '-c', 'core.fsmonitor=false', '-C', str(source), *args])
    diff = git('diff', '--binary', 'HEAD', '--')
    (evidence / (label + '-tracked.diff')).write_bytes(diff)
    status = git('status', '--porcelain=v1', '--untracked-files=all').decode()
    (evidence / (label + '-status.txt')).write_text(status)
    # Pending insta files are intentionally ignored by Git; include ignored files
    # so a different pending artifact cannot escape the permitted delta list.
    untracked = git('ls-files', '--others', '-z').decode().strip('\0').split('\0')
    untracked = [value for value in untracked if value]
    actual_hashes = {}
    hash_errors = {}
    for name in expected_hashes:
        try:
            actual_hashes[name] = digest(source / name)
        except OSError as error:
            hash_errors[name] = str(error)
    record = {'head': git('rev-parse', 'HEAD').decode().strip(),
              'tree': git('rev-parse', 'HEAD^{tree}').decode().strip(),
              'hashes': actual_hashes, 'untracked': untracked,
              'trackedDiffSha256': hashlib.sha256(diff).hexdigest(),
              'allowedUntracked': sorted(allowed_untracked), 'hashErrors': hash_errors}
    record['passed'] = (record['head'] == pin[0] and record['tree'] == pin[1]
                        and not diff and not hash_errors and actual_hashes == expected_hashes
                        and set(untracked).issubset(allowed_untracked))
    write_json(evidence / (label + '-source-state.json'), record)
    if not record['passed']:
        raise RuntimeError('Pinned source/lock invariant failed: ' + label)
    return record


def preserve_attempt(target, evidence, label, available, reserve):
    record = {'copiedJUnit': [], 'fallbackBinaryCandidates': [],
              'fallbackCandidatesAreNotProofOfExecution': True}
    for n, path in enumerate(target.glob('nextest/*/junit.xml')):
        destination = evidence / f'{label}-junit-{n}.xml'
        if not destination.exists():
            destination.write_bytes(path.read_bytes())
        record['copiedJUnit'].append(destination.name)
    retained_record = evidence / (label + '-executed-binary.json')
    retained_ok = False
    if retained_record.exists():
        retained = json.loads(retained_record.read_text())
        retained_path = evidence / retained.get('retainedPath', 'absent')
        retained_ok = retained_path.is_file() and digest(retained_path) == retained.get('sha256')
    if not retained_ok:
        import shutil
        for path in (target / 'debug/deps').glob('codex_tui-*'):
            if not path.is_file() or path.is_symlink() or not os.access(path, os.X_OK):
                continue
            with path.open('rb') as stream:
                if stream.read(4) != b'\x7fELF':
                    continue
            destination = evidence / (label + '-interrupted-' + path.name)
            if available() - path.stat().st_size < reserve:
                raise RuntimeError('Preservation would cross continuous disk reserve; retain cache')
            expected = digest(path)
            shutil.copy2(path, destination)
            if digest(destination) != expected:
                raise RuntimeError('Interrupted binary preservation mismatch; retain cache')
            record['fallbackBinaryCandidates'].append({'sourcePath': str(path), 'path': destination.name,
                                                       'bytes': destination.stat().st_size, 'sha256': expected})
    write_json(evidence / (label + '-artifact-preservation.json'), record)
    return record


def cleanup_resources(containers, records, stop_container, remove_image, remove_cache):
    result = {'containers': [], 'imageAbsent': False, 'cacheAbsent': False, 'errors': []}
    safe = all(not item.get('spawned') or (item.get('reaped') and item.get('processGroupAbsent')) for item in records)
    result['clientsQuiescent'] = safe
    for name in containers:
        try:
            stop_container(name)
            result['containers'].append({'name': name, 'absent': True})
        except BaseException as error:
            safe = False
            result['containers'].append({'name': name, 'absent': False, 'error': str(error)})
    result['safeToDeleteOwnedCaches'] = safe
    if safe:
        for field, action in [('imageAbsent', remove_image), ('cacheAbsent', remove_cache)]:
            try:
                result[field] = bool(action())
                if not result[field]:
                    result['errors'].append(field + ' not proven')
            except BaseException as error:
                result['errors'].append(field + ': ' + str(error))
    else:
        result['errors'].append('Container/client quiescence unknown; retain image/cache for runner teardown')
    result['passed'] = safe and result['imageAbsent'] and result['cacheAbsent'] and not result['errors']
    return result
