"""Synthetic fixture run only after irreversible UID/GID drop in a new hosted guest."""
import argparse
import errno
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys


def load(name, path):
    s = importlib.util.spec_from_file_location(name, path); m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m); return m


def exchange(kind, host, port, token):
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM if kind == 'tcp' else socket.SOCK_DGRAM)
    sock.settimeout(1)
    row = {'kind': kind, 'family': 'ipv6' if family == socket.AF_INET6 else 'ipv4',
           'connected': False, 'echo': False, 'errno': None, 'closed': False}
    try:
        sock.connect((host, port)); row['connected'] = True
        sock.sendall(token.encode()); row['echo'] = sock.recv(256) == token.encode()
    except OSError as e: row['errno'] = e.errno
    finally: sock.close(); row['closed'] = True
    return row


def unsupported_protocols():
    rows = []
    for name, family, kind, protocol in (
        ('raw4', socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW),
        ('raw6', socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW),
        ('icmp4', socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP),
        ('icmp6', socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_ICMPV6)):
        row = {'name': name, 'socketCreated': False, 'errno': None, 'packetsSent': 0}
        try:
            s = socket.socket(family, kind, protocol); row['socketCreated'] = True; s.close()
        except OSError as e: row['errno'] = e.errno
        rows.append(row)
    return rows


def main():
    p = argparse.ArgumentParser(); p.add_argument('--config', type=Path, required=True); a=p.parse_args()
    cfg = json.loads(a.config.read_text()); here=Path(__file__).resolve().parent
    result={'schema':'network-uid-pf-synthetic-fixture-v1','status':'INCOMPLETE','error':None,
            'uid':os.getuid(),'euid':os.geteuid(),'gid':os.getgid(),'groups':None,
            'productBodiesExecuted':0,'canaryInvocations':0,'buildInvocations':0,'canaryReady':False,'failedGates':[]}
    try:
        if sys.platform!='darwin' or os.getuid()!=cfg['uid'] or os.geteuid()!=cfg['uid']:
            raise RuntimeError('measurement_uid_mismatch')
        credentials=load('owned_kernel_credentials',here/'kernel-credentials-v1.py')
        result['kernelCredentials']=credentials.observe(cfg['uid'],cfg['gid'])
        result['groups']=result['kernelCredentials']['pythonGroupAccessList'].get('groups')
        if not result['kernelCredentials']['credentialPassed']: raise RuntimeError('measurement_groups_mismatch')
        result['homesAndMarkersMatch']=all((k in os.environ,os.environ.get(k))==tuple(v) for k,v in cfg['preserved'].items())
        if not result['homesAndMarkersMatch']: raise RuntimeError('inherited_values_changed')
        try:
            Path(cfg['runnerSentinel']).read_bytes(); result['runnerFileDenied']=False
        except OSError as e: result['runnerFileDenied']=e.errno in (errno.EPERM,errno.EACCES)
        foreign_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        foreign_socket.settimeout(1)
        try:
            foreign_socket.connect(cfg['runnerUnix']); result['runnerUnixDenied']=False
        except OSError as e: result['runnerUnixDenied']=e.errno in (errno.EPERM,errno.EACCES)
        finally: foreign_socket.close()
        own=Path(cfg['userHome'])/'own-control';own.write_bytes(b'SYNTHETIC_OWN\n')
        result['ownFileReadWrite']=own.read_bytes()==b'SYNTHETIC_OWN\n';own.unlink()
        try:
            mach=load('owned_mach',here/'mach-fixture-v2.py')
            result['mach']={'sameNameLookup':mach.lookup(cfg['machName']),
                            'runnerPerUserLookup':mach.lookup(cfg['machName'],cfg['runnerUid']),
                            'scope':'owned synthetic runner-user service only; no real credential-service calls'}
        except BaseException as exc:
            result['mach']={'errorType':type(exc).__name__}
            result['failedGates'].append('synthetic_mach_api_unavailable')
        # Explicit cross-user lookup must be rejected, not merely absent.
        if not result['runnerFileDenied'] or not result['runnerUnixDenied'] or not result['ownFileReadWrite']:
            result['failedGates'].append('uid_file_control_failed')
        if result['mach'].get('sameNameLookup') in (None,0) or result['mach'].get('runnerPerUserLookup')!=1100:
            result['failedGates'].append('runner_mach_namespace_not_isolated')  # BOOTSTRAP_NOT_PRIVILEGED
        result['unsupportedProtocols']=unsupported_protocols()
        if any(x['socketCreated'] for x in result['unsupportedProtocols']):
            result['failedGates'].append('non_tcp_udp_socket_available_pf_uid_scope_incomplete')
        result['network']={}
        for label,endpoint in cfg['endpoints'].items():
            result['network'][label]=exchange(endpoint['kind'],endpoint['host'],endpoint['port'],cfg['token'])
        expected={'tcp4','udp4','tcp6','udp6','deny_tcp4','deny_udp4'}
        if set(result['network'])!=expected: raise RuntimeError('fixed_case_set_changed')
        for name,row in result['network'].items():
            if not row['closed'] or row['echo'] != (not name.startswith('deny_')):
                result['failedGates'].append('network_control_failed_'+name)
        probe=load('pinned_broker_profile_probe',here/'synthetic-nested-seatbelt-probe-v1.py')
        sys.argv=[str(here/'synthetic-nested-seatbelt-probe-v1.py'),'--dispatch','--runtime',cfg['runtime'],
                  '--sentinel',cfg['innerSentinel'],'--foreign',cfg['runnerSentinel']]
        result['brokerProfile']=probe.main()
        if result['brokerProfile'].get('status')!='SYNTHETIC_NESTING_PATH_SUPPORTED_NOT_BROKER_QUALIFICATION':
            result['failedGates'].append('product_profile_unqualified')
        result['status']=('HOLD_SYNTHETIC_GATES_FAILED' if result['failedGates'] else
                          'SYNTHETIC_UID_PF_PROFILE_OBSERVED_NOT_CANARY_ADMISSION')
    except BaseException as e:
        result['error']=str(e) if isinstance(e,RuntimeError) else type(e).__name__
    print(json.dumps(result,sort_keys=True),flush=True)
    return 0 if result['status']=='SYNTHETIC_UID_PF_PROFILE_OBSERVED_NOT_CANARY_ADMISSION' else 2

if __name__=='__main__': sys.exit(main())
