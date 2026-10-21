#!/usr/bin/env python3
"""Hosted-only orchestrator. Admission remains false until exact packet review."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import socket
import subprocess
import sys
import threading
import time

GIB = 1024 ** 3
MARKERS = ('CODEX_SANDBOX', 'CODEX_SANDBOX_NETWORK_DISABLED', 'CODEX_SANDBOX_USER_NAMESPACES_DENIED')
REPOSITORY = 'citadelculture/CorbanuTerminal'
REF = 'refs/heads/codex/issue1177-mailbox-readiness-ci-v2-20261021'


class Hold(RuntimeError):
    pass


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2); stream.write('\n')


def select_default_route_address(routes, interfaces):
    """Exclude Docker bridges and refuse ambiguous default egress devices."""
    devices = {row.get('dev') for row in routes if row.get('dst') == 'default'
               and row.get('type', 'unicast') == 'unicast'}
    if len(devices) != 1 or None in devices:
        raise Hold('host_default_route_device_ambiguous')
    device = next(iter(devices))
    selected = [row for row in interfaces if row.get('ifname') == device]
    if len(selected) != 1:
        raise Hold('host_default_route_interface_missing')
    addresses = [row['local'] for row in selected[0].get('addr_info', [])
                 if row.get('family') == 'inet' and row.get('scope') == 'global']
    if len(addresses) != 1:
        raise Hold('host_default_route_address_ambiguous')
    return addresses[0]


def container_absent(host, name, label):
    data, _ = host.docker(label, ['container', 'ls', '--all', '--filter', 'name=^/' + name + '$', '--format', '{{.Names}}'])
    return not data.strip()


def remove_owned_container(host, name, run_id, controller_sha, owned, label):
    if container_absent(host, name, label + '-before'):
        return True
    data, _ = host.docker(label + '-identity', ['inspect', name])
    objects = json.loads(data)
    if len(objects) != 1:
        return False
    obj = objects[0]
    labels = obj.get('Config', {}).get('Labels', {}) or {}
    if (labels.get('io.corbanu.issue1177.run') != run_id
            or labels.get('io.corbanu.issue1177.controller') != controller_sha
            or not any(m.get('Source') == str(owned) and m.get('Destination') == '/owned'
                       for m in obj.get('Mounts', []))):
        return False
    host.docker(label + '-remove', ['rm', '--force', name])
    return container_absent(host, name, label + '-after')


def finalization_failure(result, reason):
    result.setdefault('primaryFailureCode', result.get('failureCode', reason))
    result.setdefault('failureCode', reason)
    result.setdefault('finalizationIssues', []).append(reason)
    result['qualified'] = False
    result['status'] = 'INCOMPLETE'


def cleanup_owned_home(owned, containers_absent, result):
    result['ownedHomeAndScratchRemoved'] = False
    if not containers_absent:
        result['ownedHomeAndScratchRetainedReason'] = 'owned_container_absence_unproven'
        finalization_failure(result, 'owned_container_absence_unproven')
        return
    try:
        for name in ('home', 'tmp', 'empty-config'):
            path = owned / name
            if path.exists(): shutil.rmtree(path)
        result['ownedHomeAndScratchRemoved'] = all(not (owned / name).exists() for name in ('home', 'tmp', 'empty-config'))
    except OSError:
        finalization_failure(result, 'owned_home_cleanup_failed')


def export_normalized(public, output, host_rows, result):
    """Withhold unsafe/unbound partial exports without masking the first failure."""
    bindings = {}
    for mode in ('acquire', 'qualify'):
        report = public / (mode + '-result.json')
        if not report.exists(): continue
        try:
            if report.is_symlink(): raise Hold('report_symlink')
            text = report.read_text()
            if re.search(r'/Users/|/home/runner|github_pat_[A-Za-z0-9_]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}', text):
                raise Hold('unsafe_report_text')
            report_data = json.loads(text)
            bindings[report.name] = (sha(report), report.stat().st_size)
            for row in report_data.get('commands', []):
                for stream in row.get('streams', {}).values():
                    bindings[stream['normalizedFile']] = (stream['normalizedSha256'], stream['normalizedBytes'])
            junit = report_data.get('junit', {})
            if 'normalizedFile' in junit:
                if junit['normalizedFile'] not in ('junit-selected.xml', 'junit-selected.xml.partial'):
                    raise Hold('junit_export_name')
                bindings[junit['normalizedFile']] = (junit['normalizedSha256'], junit['normalizedBytes'])
        except (OSError, ValueError, KeyError, TypeError, Hold):
            finalization_failure(result, mode + '_export_report_invalid')
    for row in host_rows:
        for item in row.get('normalizedDiagnostics', {}).values():
            bindings[item['file']] = (item['sha256'], item['bytes'])
    candidates = []
    for path in public.iterdir():
        identity = hashlib.sha256(path.name.encode()).hexdigest()
        try:
            if (path.name not in bindings or path.is_symlink() or not path.is_file()
                    or (path.suffix not in ('.json', '.log') and path.name not in ('junit-selected.xml', 'junit-selected.xml.partial'))):
                raise Hold('unlisted_or_unsafe_export')
            expected_sha, expected_bytes = bindings[path.name]
            if sha(path) != expected_sha or path.stat().st_size != expected_bytes:
                raise Hold('normalized_export_binding_mismatch')
            candidates.append(path)
        except (OSError, Hold):
            result.setdefault('withheldExportNameHashes', []).append(identity)
            finalization_failure(result, 'unlisted_unsafe_or_partial_export_withheld')
    total = sum(path.stat().st_size for path in candidates)
    result['normalizedExportBytes'] = total
    # Reserve one MiB within the 16MiB ceiling for safe host-result metadata.
    if total > 15 * 1024 ** 2:
        finalization_failure(result, 'normalized_export_bound')
        candidates = [path for path in candidates if path.name in ('acquire-result.json', 'qualify-result.json')]
    result['exportedFiles'] = []
    for path in candidates:
        try:
            shutil.copyfile(path, output / path.name)
            result['exportedFiles'].append({'name': path.name, 'sha256': sha(path), 'bytes': path.stat().st_size})
        except OSError:
            finalization_failure(result, 'normalized_export_copy_failed')


class Host:
    def __init__(self, root, control):
        self.root, self.control, self.rows = root, control, []

    def run(self, label, argv, seconds=60, allow_failure=False):
        """Finite host commands, never stream raw host output into Actions logs."""
        out = self.root / 'host-raw' / (label + '.stdout')
        err = self.root / 'host-raw' / (label + '.stderr')
        process, reason, complete, cleanup_failure = None, None, False, None
        started = time.monotonic()
        with out.open('xb') as stdout, err.open('xb') as stderr, selectors.DefaultSelector() as select:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, start_new_session=True)
            counts = {'stdout': 0, 'stderr': 0}
            handles = {'stdout': stdout, 'stderr': stderr}
            for name, pipe in (('stdout', process.stdout), ('stderr', process.stderr)):
                os.set_blocking(pipe.fileno(), False); select.register(pipe, selectors.EVENT_READ, name)
            try:
                while process.poll() is None or select.get_map():
                    if time.monotonic() - started > seconds: raise Hold('host_phase_timeout')
                    if shutil.disk_usage(self.root).free < 10 * GIB: raise Hold('host_disk_floor')
                    for key, _ in select.select(.2):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            select.unregister(key.fileobj); key.fileobj.close(); continue
                        counts[key.data] += len(chunk)
                        if counts[key.data] > 64 * 1024 ** 2: raise Hold('host_output_bound')
                        handles[key.data].write(chunk)
                process.wait(); complete = True
            except Hold as error:
                reason = str(error)
                try:
                    try: os.killpg(process.pid, 15)
                    except ProcessLookupError: pass
                    try: process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        try: os.killpg(process.pid, 9)
                        except ProcessLookupError: pass
                        process.wait(timeout=5)
                except Exception:
                    cleanup_failure = 'host_command_cleanup_incomplete'
            finally:
                for key in list(select.get_map().values()):
                    select.unregister(key.fileobj); key.fileobj.close()
        self.rows.append({'phase': label, 'exitCode': process.returncode, 'captureComplete': complete,
            'seconds': round(time.monotonic()-started, 3), 'failureCode': reason,
            'cleanupFailureCode': cleanup_failure,
            'stdoutSha256': sha(out), 'stdoutBytes': out.stat().st_size,
            'stderrSha256': sha(err), 'stderrBytes': err.stat().st_size})
        # Only these diagnostic-producing phases may export host text. Machine
        # inventories (inspect/address/state) are parsed to booleans and hashes.
        if label in ('build-native-image', 'run-acquire', 'run-qualify'):
            for name, path in (('stdout', out), ('stderr', err)):
                text = path.read_bytes().decode('utf-8', 'replace')
                for original, replacement in ((str(self.root), '[HOST_OWNED]'),
                    (os.environ.get('GITHUB_WORKSPACE', ''), '[WORKSPACE]'),
                    (os.environ.get('HOME', ''), '[RUNNER_HOME]')):
                    if original: text = text.replace(original, replacement)
                if re.search(r'github_pat_[A-Za-z0-9_]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|/Users/|/home/runner', text):
                    raise Hold('host_output_export_hold')
                lines, redacted = [], 0
                for line in text.splitlines(keepends=True):
                    if re.search(r'(?i)(?:\benviron(?:ment)?\s*[:={]|(?:API_KEY|AUTH_TOKEN|OAUTH_TOKEN|SECRET_ACCESS_KEY)\s*[:=]|stack backtrace:|traceback \(most recent call|^\s*\d+:\s|^\s*at (?:/|\[)|^\s*File ")', line):
                        lines.append('[REDACTED_ENVIRONMENT_OR_STACK_LINE]\n'); redacted += 1
                    else: lines.append(line)
                export = self.root / 'owned/public' / ('host-' + label + '-' + name + '.log')
                export.write_text(''.join(lines))
                self.rows[-1].setdefault('normalizedDiagnostics', {})[name] = {
                    'file': export.name, 'sha256': sha(export), 'bytes': export.stat().st_size, 'redactedLines': redacted}
        if reason or (process.returncode and not allow_failure): raise Hold(label + '_failed')
        return out.read_bytes(), process.returncode

    def docker(self, label, args, seconds=60, allow_failure=False):
        return self.run(label, ['docker', *args], seconds, allow_failure)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dispatch', action='store_true', required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--control', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if (platform.system() != 'Linux' or platform.machine() != 'x86_64' or os.geteuid() == 0
            or sys.version_info < (3, 12) or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or os.environ.get('GITHUB_REPOSITORY') != REPOSITORY or os.environ.get('GITHUB_REF') != REF
            or os.environ.get('GITHUB_RUN_ATTEMPT') != '1' or os.environ.get('GITHUB_EVENT_NAME') != 'push'):
        raise Hold('fixed_first_attempt_hosted_context_required')
    # These are never cleared or forwarded from a live profile into this lane.
    if any(k in os.environ for k in ('CODEX_HOME', 'CORBANU_HOME', 'PFTERMINAL_HOME')):
        raise Hold('inherited_profile_identity_present')
    if any(k.startswith('CODEX_SANDBOX') and k not in MARKERS for k in os.environ):
        raise Hold('unrecognized_inherited_sandbox_control')
    control = args.control.resolve()
    admission = json.loads((control / 'admission.json').read_text())
    if admission.get('approved') is not True: raise Hold('admission_false')
    review = admission.get('reviewReceiptSha256', '')
    if not isinstance(review, str) or len(review) != 64 or any(x not in '0123456789abcdef' for x in review):
        raise Hold('review_binding_missing')
    expected_files = {'controller.py', 'worker.py', 'boundary_probe.py', 'Dockerfile',
        'tools-pins.json', 'source-manifest.json', 'change.patch', 'METHOD.txt',
        '.github/workflows/issue1177-mailbox-readiness-v2.yml'}
    if set(admission.get('files', {})) != expected_files: raise Hold('admission_file_set')
    for name, expected in admission['files'].items():
        if (control / name).is_symlink() or sha(control / name) != expected: raise Hold('admission_hash_mismatch')
    identity = os.environ.get('GITHUB_RUN_ID', '')
    if not identity.isdecimal(): raise Hold('run_id')
    root = Path('/tmp') / ('issue1177-hosted-' + identity)
    root.mkdir(mode=0o700)
    public_control = root / 'public-control'; public_control.mkdir()
    for name in expected_files | {'admission.json'}:
        destination = public_control / name; destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(control / name, destination)
    control = public_control
    (root / 'host-raw').mkdir(); (root / 'build-context').mkdir()
    owned = root / 'owned'; owned.mkdir()
    for name in ('home', 'tmp', 'empty-config', 'cargo-home', 'unused-rustup', 'target', 'uv-cache',
                 'dotslash-cache', 'bin', 'toolchain', 'downloads', 'unpacked', 'raw', 'public',
                 'acquisition-metadata-target'):
        (owned / name).mkdir(mode=0o700)
    (owned / 'empty-netrc').write_text('')
    shutil.copytree(args.source, owned / 'source', symlinks=True)
    shutil.copyfile(control / 'Dockerfile', root / 'build-context/Dockerfile')
    host = Host(root, control)
    result = {'schema': 'issue1177-hosted-result-v2', 'qualified': False, 'runAttempt': 1,
        'runId': identity, 'commands': host.rows, 'admissionSha256': sha(control / 'admission.json'),
        'controllerSha256': sha(__file__), 'rawRetention': 'Ephemeral runner-only; raw host or child logs are never uploaded.'}
    containers, listener, thread, stop, canary = [], None, None, threading.Event(), None
    code = 1
    try:
        result['initialFreeBytes'] = shutil.disk_usage(root).free
        memory = int(Path('/proc/meminfo').read_text().split('MemTotal:')[1].split()[0]) * 1024
        result['hostMemoryBytes'] = memory
        if result['initialFreeBytes'] < 30 * GIB or memory < 12 * GIB: raise Hold('initial_capacity_floor')
        # Host-side positive control is a real, responsive listener throughout qualification.
        ips, _ = host.run('host-addresses', ['ip', '-j', '-4', 'address', 'show', 'scope', 'global'])
        routes, _ = host.run('host-default-routes', ['ip', '-j', '-4', 'route', 'show', 'default'])
        address = select_default_route_address(json.loads(routes), json.loads(ips))
        listener = socket.socket(); listener.settimeout(.2); listener.bind(('0.0.0.0', 0)); listener.listen(4)
        def serve():
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                    with conn:
                        conn.settimeout(1)
                        if conn.recv(64) == b'issue1177-host-control': conn.sendall(b'host-control-positive')
                except socket.timeout: pass
                except OSError: break
        thread = threading.Thread(target=serve); thread.start()
        def positive():
            with socket.create_connection((address, listener.getsockname()[1]), timeout=2) as client:
                client.sendall(b'issue1177-host-control')
                return client.recv(64) == b'host-control-positive'
        result['outsideListenerPositiveBefore'] = positive()
        if not result['outsideListenerPositiveBefore']: raise Hold('outside_positive_control_failed')
        canary = root / 'host-only-synthetic-canary'; canary.write_text('synthetic host-only boundary canary\n')
        proof = {'pid': os.getpid(), 'pidNamespace': os.readlink('/proc/self/ns/pid'),
            'netNamespace': os.readlink('/proc/self/ns/net'), 'canary': str(canary),
            'listenerAddress': address, 'listenerPort': listener.getsockname()[1]}
        save(owned / 'host-proof.json', proof)
        dockerfile = str(root / 'build-context')
        host.docker('build-native-image', ['build', '--pull', '--no-cache', '--network=default',
            '--build-arg', 'WORKER_UID=' + str(os.getuid()), '--build-arg', 'WORKER_GID=' + str(os.getgid()),
            '--iidfile', str(root / 'image-id'), dockerfile], 900)
        image_id = (root / 'image-id').read_text().strip()
        if not image_id.startswith('sha256:') or len(image_id) != 71: raise Hold('image_identity')
        result['nativeImageId'] = image_id
        for mode, network, timeout in (('acquire', 'bridge', 1550), ('qualify', 'none', 5550)):
            if mode == 'qualify' and shutil.disk_usage(root).free < 30 * GIB: raise Hold('before_worker_capacity_floor')
            name = 'issue1177-' + identity + '-' + mode
            command = ['create', '--name', name, '--network', network, '--read-only',
                '--label', 'io.corbanu.issue1177.run=' + identity,
                '--label', 'io.corbanu.issue1177.controller=' + sha(__file__),
                '--user', str(os.getuid()) + ':' + str(os.getgid()), '--cap-drop', 'ALL',
                '--security-opt', 'no-new-privileges:true', '--pids-limit', '512',
                '--memory', '12g', '--memory-swap', '12g', '--cpus', '2',
                '--ipc', 'private', '--tmpfs', '/tmp:rw,nosuid,nodev,size=256m',
                '--ulimit', 'core=0', '--mount', 'type=bind,src=' + str(owned) + ',dst=/owned',
                '--mount', 'type=bind,src=' + str(control) + ',dst=/control,readonly',
                '--env', 'HOME=/owned/home']
            for marker in MARKERS:
                if marker in os.environ: command += ['--env', marker]
            command += [image_id, '/usr/bin/python3', '-I', '-B', '/control/worker.py', mode]
            # Register before create so an ambiguous CLI outcome still reconciles
            # this exact run-owned name and labels in the final cleanup path.
            containers.append(name)
            host.docker('create-' + mode, command)
            inspected, _ = host.docker('inspect-' + mode, ['inspect', name])
            obj = json.loads(inspected)[0]; cfg = obj['HostConfig']
            mounts = obj['Mounts']
            exact_mounts = {(m['Source'], m['Destination'], m['RW']) for m in mounts if m['Type'] == 'bind'}
            extra_mounts = [m for m in mounts if m['Type'] != 'bind' and not (m['Type'] == 'tmpfs' and m['Destination'] == '/tmp')]
            valid = (cfg['NetworkMode'] == network and cfg['ReadonlyRootfs'] is True
                and cfg['Privileged'] is False and cfg['CapDrop'] == ['ALL'] and not extra_mounts
                and cfg['PidMode'] == '' and cfg['IpcMode'] == 'private'
                and cfg['PidsLimit'] == 512 and cfg['Memory'] == 12*GIB and cfg['MemorySwap'] == 12*GIB
                and 'no-new-privileges:true' in cfg['SecurityOpt']
                and exact_mounts == {(str(owned), '/owned', True), (str(control), '/control', False)})
            result.setdefault('containerConfiguration', {})[mode] = {'verified': valid, 'network': network,
                'privatePidAndIpc': True, 'capabilitiesDropped': 'ALL', 'memoryBytes': 12*GIB, 'pidsLimit': 512,
                'publicOwnedAndReadOnlyControlMountsOnly': valid, 'imageId': image_id}
            if not valid: raise Hold('container_configuration_mismatch')
            _, exit_code = host.docker('run-' + mode, ['start', '--attach', name], timeout, allow_failure=True)
            state_json, _ = host.docker('state-' + mode, ['inspect', '--format', '{{json .State}}', name])
            state = json.loads(state_json)
            result.setdefault('containerExit', {})[mode] = {'exitCode': state['ExitCode'], 'oomKilled': state['OOMKilled'], 'running': state['Running']}
            host.docker('remove-' + mode, ['rm', name])
            if not container_absent(host, name, 'absence-' + mode):
                raise Hold('owned_container_removal_unconfirmed')
            containers.remove(name)
            worker_path = owned / 'public' / (mode + '-result.json')
            if not worker_path.is_file(): raise Hold(mode + '_worker_result_missing')
            worker = json.loads(worker_path.read_text())
            result[mode + 'ResultSha256'] = sha(worker_path)
            if exit_code or state['ExitCode'] or state['OOMKilled'] or state['Running'] or worker['status'] == 'INCOMPLETE':
                raise Hold(mode + '_failed')
        result['outsideListenerPositiveAfter'] = positive()
        result['hostCanaryUnchanged'] = canary.read_text() == 'synthetic host-only boundary canary\n'
        result['qualified'] = result['outsideListenerPositiveAfter'] and result['hostCanaryUnchanged'] and worker['qualified']
        if not result['qualified']: raise Hold('final_controls_failed')
        result['status'] = 'FOUR_CASES_PASSED'; code = 0
    except BaseException as error:
        result['status'] = 'INCOMPLETE'
        result['failureCode'] = str(error) if isinstance(error, Hold) else 'controller_' + type(error).__name__
        result['primaryFailureCode'] = result['failureCode']
        result['qualified'] = False
    finally:
        result['ownedContainersRemoved'] = True
        for name in containers:
            try:
                removed = remove_owned_container(host, name, identity, sha(__file__), owned,
                    'cleanup-' + name.rsplit('-', 1)[-1])
                result['ownedContainersRemoved'] = result['ownedContainersRemoved'] and removed
            except Exception:
                result['ownedContainersRemoved'] = False
        stop.set()
        if listener: listener.close()
        if thread: thread.join(3)
        result['hostControlThreadStopped'] = not thread or not thread.is_alive()
        if canary:
            try: canary.unlink(missing_ok=True)
            except OSError: finalization_failure(result, 'host_canary_cleanup_failed')
        # Remove only this newly created run's HOME/scratch. Sources, binaries and
        # raw captures remain until the hosted runner is disposed; none are uploaded.
        cleanup_owned_home(owned, result['ownedContainersRemoved'], result)
        if not result['ownedContainersRemoved'] or not result['hostControlThreadStopped']:
            finalization_failure(result, 'owned_container_or_host_thread_cleanup_incomplete')
        args.output.mkdir(mode=0o700)
        try:
            export_normalized(owned / 'public', args.output, host.rows, result)
        except Exception:
            finalization_failure(result, 'normalized_export_finalization_failed')
        save(args.output / 'host-result.json', result)
        print(result['status'])
        code = 0 if result['qualified'] else 1
    return code


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print('HOSTED_NOT_STARTED:' + (str(error) if isinstance(error, Hold) else type(error).__name__))
        sys.exit(1)
