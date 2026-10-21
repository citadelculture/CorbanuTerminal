#!/usr/bin/env python3
"""Synthetic containment controls; no repository code or credential values."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading


def probe():
    proof = json.loads(Path('/owned/host-proof.json').read_text())
    checks = {}
    checks['nonroot'] = os.geteuid() != 0
    checks['private_pid_namespace'] = os.readlink('/proc/self/ns/pid') != proof['pidNamespace']
    checks['private_network_namespace'] = os.readlink('/proc/self/ns/net') != proof['netNamespace']
    checks['host_canary_direct_denied'] = not Path(proof['canary']).exists()
    checks['host_canary_proc_root_denied'] = not Path(
        '/proc/' + str(proof['pid']) + '/root' + proof['canary']).exists()
    checks['host_mounts_absent'] = all(not Path(p).exists() for p in (
        '/var/run/docker.sock', '/run/docker.sock', '/run/dbus/system_bus_socket',
        '/run/secrets', '/github', '/home/runner', '/Users'))
    checks['credential_environment_absent'] = not any(
        key in os.environ for key in ('GITHUB_TOKEN', 'GH_TOKEN', 'ACTIONS_RUNTIME_TOKEN',
        'OPENAI_API_KEY', 'CODEX_API_KEY', 'ANTHROPIC_API_KEY', 'ZAI_API_KEY',
        'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'SSH_AUTH_SOCK', 'DBUS_SESSION_BUS_ADDRESS'))
    checks['only_loopback_interface'] = sorted(p.name for p in Path('/sys/class/net').iterdir()) == ['lo']
    for family, address, label in ((socket.AF_INET, '127.0.0.1', 'ipv4'),
                                    (socket.AF_INET6, '::1', 'ipv6')):
        listener = socket.socket(family, socket.SOCK_STREAM)
        listener.settimeout(2)
        listener.bind((address, 0)); listener.listen(1)
        errors = []
        def serve():
            try:
                peer, _ = listener.accept()
                with peer:
                    peer.settimeout(2)
                    if peer.recv(32) != b'issue1177-loopback':
                        errors.append(True)
                    peer.sendall(b'owned-loopback-ok')
            except OSError:
                errors.append(True)
        thread = threading.Thread(target=serve)
        thread.start()
        try:
            with socket.socket(family, socket.SOCK_STREAM) as client:
                client.settimeout(2); client.connect(listener.getsockname())
                client.sendall(b'issue1177-loopback')
                checks['positive_loopback_' + label] = client.recv(32) == b'owned-loopback-ok'
        except OSError:
            checks['positive_loopback_' + label] = False
        thread.join(3); listener.close()
        checks['loopback_server_' + label + '_clean'] = not errors and not thread.is_alive()
    for address, port, label in ((proof['listenerAddress'], proof['listenerPort'], 'live_host_listener'),
                                  ('169.254.169.254', 80, 'link_local_metadata')):
        try:
            with socket.create_connection((address, port), timeout=1):
                checks['negative_' + label] = False
        except OSError:
            checks['negative_' + label] = True
    owned = Path('/owned/tmp/probe-owned-write')
    owned.write_text('synthetic owned content')
    checks['positive_owned_write'] = owned.read_text() == 'synthetic owned content'
    owned.unlink()
    checks['passed'] = all(checks.values())
    return checks


if __name__ == '__main__':
    result = {'executor': probe()}
    if '--child' not in sys.argv:
        child = subprocess.run([sys.executable, '-I', '-B', __file__, '--child'],
                               capture_output=True, text=True, timeout=20, check=False)
        result['child'] = json.loads(child.stdout)['executor'] if child.returncode == 0 else {'passed': False}
    print(json.dumps(result, sort_keys=True))
    sys.exit(0 if all(x['passed'] for x in result.values()) else 1)
