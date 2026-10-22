"""Actual restricted-container positive/negative controls; no product execution."""
import json
import hashlib
import os
import pathlib
import shutil
import socket
import subprocess
from hosted_controls import digest
from tool_manifest import observe_tools, compare_tools

status = pathlib.Path('/proc/self/status').read_text()
fields = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
assert fields['Seccomp'].strip() == '2', 'default seccomp filter absent'
assert fields['NoNewPrivs'].strip() == '1', 'no-new-privileges absent'
assert int(fields['CapEff'].strip(), 16) == 0, 'effective capabilities remain'
assert os.getuid() != 0, 'native workload must use a non-root UID'
assert not pathlib.Path('/var/run/docker.sock').exists()
assert not pathlib.Path('/run/docker.sock').exists()
assert not pathlib.Path('/host').exists()
assert not pathlib.Path('/run/dbus/system_bus_socket').exists()
assert sorted(p.name for p in pathlib.Path('/sys/class/net').iterdir()) == ['lo']
probe = socket.socket()
probe.settimeout(2)
try:
    probe.connect(('1.1.1.1', 443))
except OSError:
    pass
else:
    raise AssertionError('unexpected external network reachability')
finally:
    probe.close()
try:
    pathlib.Path('/etc/issue1094-write-probe').write_text('not allowed')
except OSError:
    pass
else:
    raise AssertionError('container root filesystem is writable')
for name in ('mnt', 'pid', 'ipc', 'net'):
    assert os.readlink('/proc/self/ns/' + name) != os.environ['HOST_NS_' + name.upper()]
for directory in ('/scratch', '/out', '/cache'):
    probe_path = pathlib.Path(directory) / 'issue1094-positive-control'
    probe_path.write_text('synthetic fixture only\n')
    assert probe_path.read_text() == 'synthetic fixture only\n'
    probe_path.unlink()
manifest = pathlib.Path('/opt/issue1094-tool-manifest.json')
assert digest(manifest) == os.environ['EXPECTED_TOOL_MANIFEST_SHA256']
tools = observe_tools()
compare_tools(json.loads(manifest.read_text()), tools)
print(json.dumps({'state': 'RESTRICTED_CONTAINER_CONTROLS_PASS',
                  'uid': os.getuid(), 'seccomp': 2, 'capEff': 0,
                  'noNewPrivileges': True, 'externalNetworkDenied': True,
                  'privateNamespaces': ['mnt', 'pid', 'ipc', 'net'],
                  'tools': tools,
                  'productExecution': False}, sort_keys=True))
