#!/usr/bin/env python3
"""INERT until exact reviewed hosted admission. Synthetic UID/PF capability only."""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import stat
import sys
import threading
import time
import uuid

REPO = 'citadelculture/CorbanuTerminal'
BRANCH = 'refs/heads/codex/network-kernel-groups-reentry-v1-20261021'
CONTEXT = ('RUNNER_ENVIRONMENT','RUNNER_OS','GITHUB_REPOSITORY','GITHUB_REF','GITHUB_EVENT_NAME','GITHUB_RUN_ATTEMPT','GITHUB_RUN_ID')
PRESERVED = ('HOME','CODEX_HOME','CODEX_SANDBOX','CODEX_SANDBOX_NETWORK_DISABLED')
CODE = ('capability-controller-v8.py','mach-fixture-v2.py','measurement-fixture-v2.py',
        'synthetic-nested-seatbelt-probe-v1.py','bounded-command-v3.py','child-bootstrap-v2.py',
        'account-observation-v1.py','kernel-credentials-v1.py')
GIB = 1024**3
MAX_COMMANDS = 70
CLEANUP_KEYS = {'listenersClosed','measurementUidNoProcesses','runtimeRemoved','ownedAnchorEmpty',
                'ownedPfReferenceReleased','ownedUserRemoved','ownedGroupRemoved','mainRulesUnchanged','allRecordedGroupsGone'}


def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def write(p, value):
    with Path(p).open('x') as f: json.dump(value,f,indent=2,sort_keys=True); f.write('\n')


def load(name,p):
    s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s)
    s.loader.exec_module(m);return m


def require(condition, reason):
    if not condition: raise RuntimeError(reason)


def credential_failure_observation(uid, gid, actual_uid, actual_euid, groups):
    """Numeric state only; this observation never decides admission."""
    require(type(uid) is int and 60000<=uid<64000 and gid==uid,'diagnostic_owned_uid_required')
    require(all(type(v) is int and 0<=v<2**32 for v in (actual_uid,actual_euid)),
            'diagnostic_uid_shape')
    require(type(groups) is list and all(type(v) is int and 0<=v<2**32 for v in groups),
            'diagnostic_groups_shape')
    return {'schema':'credential-drop-state-v1','expectedUid':uid,'expectedGroups':[gid],
            'actualUid':actual_uid,'actualEuid':actual_euid,'actualGroups':groups[:32],
            'actualGroupCount':len(groups),'groupsTruncated':len(groups)>32,
            'predicatePassed':False,'scope':'state-only; original credential_drop_failed remains'}


def owned_process_selection(text):
    """Only exact PIDs already returned by the existing owned-UID probe."""
    require(type(text) is str and len(text.encode())<=4096,'diagnostic_pid_input_bound')
    lines=text.splitlines()
    require(1<=len(lines)<=16,'diagnostic_pid_count_bound')
    require(all(re.fullmatch('[1-9][0-9]{0,9}',v) and int(v)<2**31 for v in lines),
            'diagnostic_pid_shape')
    pids=list(map(int,lines))
    require(len(set(pids))==len(pids),'diagnostic_duplicate_pid')
    return pids


def process_state_rows(text, pids, uid):
    """No command names, argv, paths or environment; snapshots are racy."""
    require(type(text) is str and len(text.encode())<=16384,'diagnostic_ps_output_bound')
    rows=[];seen=set()
    for line in text.splitlines():
        fields=line.split()
        require(len(fields)==8 and all(re.fullmatch('[0-9]{1,10}',v) for v in fields[:7])
                and re.fullmatch('[A-Za-z0-9+<>=-]{1,16}',fields[7]),'diagnostic_ps_shape')
        values=list(map(int,fields[:7]));pid=values[0]
        require(all(v<2**32 for v in values) and pid in pids and pid not in seen,
                'diagnostic_ps_identity')
        seen.add(pid)
        row=dict(zip(('pid','parentPid','processGroupId','effectiveUid','realUid',
                      'effectiveGid','realGid'),values))
        row.update(state=fields[7],ownedUidMatches=values[3]==uid and values[4]==uid)
        rows.append(row)
    return {'rows':rows,'selectedPidsAbsentFromSnapshot':[p for p in pids if p not in seen],
            'limitation':'PID reuse/disappearance is possible; numeric snapshot never clears the original UID-process hold.'}


def observe_owned_uid_processes(calls, raw, uid):
    observation={'schema':'owned-uid-process-state-v1','expectedUid':uid,
                 'scope':'state-only; original cleanup hold remains','queryAttempted':False}
    try:
        require(type(uid) is int and 60000<=uid<64000,'diagnostic_owned_uid_required')
        previous=[r for r in calls.rows if r['label']=='uid-processes']
        require(len(previous)==1,'diagnostic_original_probe_required')
        probe=previous[0]
        require(probe['exitCode']==0 and probe['captureComplete'] and probe['groupGone']
                and probe['stopReason'] is None
                and all(not v['truncated'] for v in probe['capture'].values()),
                'diagnostic_original_probe_incomplete')
        with (raw/'uid-processes.stdout').open('rb') as stream:data=stream.read(4097)
        require(len(data)<=4096 and hashlib.sha256(data).hexdigest()==probe['stdoutSha256']
                and len(data)==probe['stdoutBytes'],'diagnostic_original_probe_changed')
        pids=owned_process_selection(data.decode('ascii'))
        argv=['/bin/ps','-p',','.join(map(str,pids)),
              '-o','pid=,ppid=,pgid=,uid=,ruid=,gid=,rgid=,state=']
        observation.update(selectedPids=pids,queryAttempted=True)
        text=calls.run('uid-process-state',argv,allowed=(0,1),seconds=5,cleanup=True,capture_limit=16384)
        observation.update(process_state_rows(text,pids,uid))
    except BaseException as exc:
        observation['observationError']=str(exc) if isinstance(exc,RuntimeError) else type(exc).__name__
    return observation


def environment(original):
    # HOME/CODEX_HOME are never rebound. New UID cannot traverse the runner home.
    result={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'}
    for k in PRESERVED:
        if k in original: result[k]=original[k]
    return result


def hosted_guard(env, sys_platform, release, machine, uid):
    require(sys_platform=='darwin' and release.split('.')[0]=='24' and machine=='arm64','macos15_arm64_required')
    require(uid>0 and env.get('RUNNER_ENVIRONMENT')=='github-hosted' and env.get('RUNNER_OS')=='macOS','fresh_nonroot_hosted_required')
    require(env.get('GITHUB_REPOSITORY')==REPO and env.get('GITHUB_REF')==BRANCH,'fixed_route_required')
    require(env.get('GITHUB_EVENT_NAME')=='push' and env.get('GITHUB_RUN_ATTEMPT')=='1','one_push_attempt_required')
    require(re.fullmatch('[0-9]{8,16}',env.get('GITHUB_RUN_ID','')) is not None,'run_id_required')


def scoped_rules(uid):
    require(type(uid) is int and 60000<=uid<64000,'uid_out_of_owned_range')
    # The existing main com.apple/* hook must exist; these rules affect only this UID.
    return ('pass out quick on lo0 inet proto { tcp udp } from 127.0.0.0/8 to 127.0.0.0/8 '
            f'user {uid} keep state label "ncap_allow4"\n'
            'pass out quick on lo0 inet6 proto { tcp udp } from ::1 to ::1 '
            f'user {uid} keep state label "ncap_allow6"\n'
            f'block drop out quick proto {{ tcp udp }} user {uid} label "ncap_denyout"\n'
            f'block drop in quick proto {{ tcp udp }} user {uid} label "ncap_denyin"\n')


def enable_token(text):
    matches=re.findall(r'(?m)^Token\s*:\s*([0-9]+)\s*$',text)
    require(len(matches)==1,'owned_pf_token_not_unique')
    return matches[0]


def parse_labels(text):
    # Fixed four-rule source expands each {tcp udp} list into two rules.
    # Labels identify rule groups, not unique rules. Retain each ordered row.
    labels=('ncap_allow4','ncap_allow6','ncap_denyout','ncap_denyin')
    fields_expected=('evaluations','packets','bytes','packetsIn','bytesIn','packetsOut','bytesOut')
    expected=tuple(label for label in labels for _ in range(2))
    require(isinstance(text,str) and len(text)<=4096,'pf_labels_input_bound')
    lines=text.splitlines()
    require(len(lines)==len(expected),'pf_label_row_count')
    rows={label:{'expandedRules':[]} for label in labels}
    for line,label in zip(lines,expected):
        fields=line.split()
        require(len(fields)==8 and fields[0]==label,'pf_label_order_or_identity')
        require(all(re.fullmatch(r'[0-9]{1,20}',v) for v in fields[1:]),'pf_label_format_unknown')
        values=list(map(int,fields[1:]))
        require(all(v<2**64 for v in values),'pf_counter_range')
        row=dict(zip(fields_expected,values))
        require(row['packets']==row['packetsIn']+row['packetsOut']
                and row['bytes']==row['bytesIn']+row['bytesOut'],'pf_counter_total_mismatch')
        rows[label]['expandedRules'].append(row)
    for label in labels:
        for field in fields_expected:
            total=sum(row[field] for row in rows[label]['expandedRules'])
            require(total<2**64,'pf_counter_aggregate_range')
            rows[label][field]=total
    return rows


def packet_deltas(before,after):
    # Reject any observed per-row counter regression before taking group sums.
    require(set(before)==set(after),'pf_counter_labels_changed')
    for label in before:
        require(len(before[label]['expandedRules'])==len(after[label]['expandedRules'])==2,
                'pf_counter_shape_changed')
        for old,new in zip(before[label]['expandedRules'],after[label]['expandedRules']):
            require(set(old)==set(new) and all(new[k]>=old[k] for k in old),
                    'pf_counter_regression')
    return {label:after[label]['packets']-before[label]['packets'] for label in before}


def observe_account_absence(lookup,name,owned=None):
    """One exact existing libc lookup; never flush caches, retry, or print records."""
    try:
        value=lookup(name)
    except KeyError:
        return {'state':'absent','removed':True}
    except BaseException as exc:
        return {'state':'lookup-error','removed':False,'exceptionType':type(exc).__name__}
    result={'state':'present','removed':False}
    if owned is not None:
        result['identityMatches']={'name':getattr(value,'pw_name',None)==name,
                                   'uid':getattr(value,'pw_uid',None)==owned['uid'],
                                   'gid':getattr(value,'pw_gid',None)==owned['gid']}
    return result


def pf_command_allowed(argv, anchor, rules, token=None):
    if argv==['/sbin/pfctl','-sr'] or argv==['/sbin/pfctl','-s','info'] or argv==['/sbin/pfctl','-E']: return True
    if token is not None and argv==['/sbin/pfctl','-X',token]: return True
    return argv in [['/sbin/pfctl','-a',anchor,*tail] for tail in
                    (['-sr'],['-s','labels'],['-nf',str(rules)],['-f',str(rules)],['-F','rules'])]


def public_projection(data, run_id):
    """Only a complete exact owned DS record token may be normalized; all other user paths hold."""
    require(re.fullmatch(r'[0-9]{8,16}',run_id) is not None,'projection_run_id_invalid')
    record=('/Users/_ncap'+run_id).encode()
    pattern=rb"(?<![A-Za-z0-9_./-])"+re.escape(record)+rb"(?=$|[\s\"')\]}])"
    public,count=re.subn(pattern,b'<OWNED_DS_USER_RECORD>',data)
    require(b'/Users/' not in public,'remaining_private_user_path')
    require(not re.search(rb'(?i)(?:github_pat_|gh[pousr]_|Bearer\s|PRIVATE KEY)',public),'sensitive_shape_export_hold')
    return public,{'originalSha256':hashlib.sha256(data).hexdigest(),'originalBytes':len(data),
                   'publicSha256':hashlib.sha256(public).hexdigest(),'publicBytes':len(public),
                   'normalizationCount':count,'linesUnchanged':data.count(b'\n')==public.count(b'\n')}


def record_failure(result, phase, code):
    """Preserve the primary cause and every secondary failure; never upgrade status."""
    require(phase in ('primary','cleanup','reporting'),'unknown_failure_phase')
    if phase=='primary':
        if result['primaryFailure'] is None:
            result['primaryFailure']=code
    else:
        result[phase+'Failures'].append(code)
    if result['error'] is None:
        result['error']=code
    result['status']='HOLD_CAPABILITY_INCOMPLETE'


def capability_status(fixture, cleanup, counter_delta, root_positive):
    ok=(fixture.get('status')=='SYNTHETIC_UID_PF_PROFILE_OBSERVED_NOT_CANARY_ADMISSION'
        and set(cleanup)==CLEANUP_KEYS and all(cleanup.values()) and all(counter_delta.get(k,0)>0 for k in ('ncap_allow4','ncap_allow6','ncap_denyout'))
        and root_positive is True)
    return 'SYNTHETIC_CAPABILITY_PASSED_NOT_CANARY_ADMISSION' if ok else 'HOLD_CAPABILITY_INCOMPLETE'


class Calls:
    def __init__(self, code, raw, root, env, seconds=210):
        self.m=load('bounded_command',code/'bounded-command-v3.py');self.raw=raw;self.root=root
        self.env=env;self.rows=[];self.deadline=time.monotonic()+seconds;self.code=code;self.cleanup_deadline=None
    def run(self,label,argv,allowed=(0,),seconds=12,cleanup=False,env=None,capture_limit=8*1024**2):
        require(len(self.rows)<MAX_COMMANDS,'command_count_bound')
        if cleanup and self.cleanup_deadline is None:self.cleanup_deadline=time.monotonic()+60
        deadline=self.cleanup_deadline if cleanup else self.deadline
        before=len(self.rows)
        try: self.m.command(label,argv,self.root,env or self.env,self.raw,self.rows,deadline,seconds,self.root,
                            capture_limit=capture_limit)
        except self.m.Hold:
            require(len(self.rows)==before+1,'command_not_recorded')
        row=self.rows[-1]
        require(row['exitCode'] in allowed and row['captureComplete'] and row['groupGone']
                and row['stopReason'] is None and all(not x['truncated'] for x in row['capture'].values()),label+'_unqualified')
        return (self.raw/(label+'.stdout')).read_text()


class Echoes:
    """Six bounded owned listeners only; no external hosts, DNS or TLS stores."""
    def __init__(self, address, token):
        self.token=token.encode(); self.stop=threading.Event(); self.sockets=[];self.threads=[];self.counts={};self.endpoints={}
        self.address=address
    def start(self):
        for name,kind,host in [('tcp4','tcp','127.0.0.1'),('udp4','udp','127.0.0.1'),
                               ('tcp6','tcp','::1'),('udp6','udp','::1'),
                               ('deny_tcp4','tcp',self.address),('deny_udp4','udp',self.address)]:
            s=socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET,socket.SOCK_STREAM if kind=='tcp' else socket.SOCK_DGRAM)
            self.sockets.append(s);s.settimeout(.2);s.bind((host,0))
            if kind=='tcp': s.listen(2)
            self.endpoints[name]={'kind':kind,'host':host,'port':s.getsockname()[1]};self.counts[name]=0
            t=threading.Thread(target=self.serve,args=(name,kind,s),daemon=True);t.start();self.threads.append(t)
        return self
    def serve(self,name,kind,s):
        while not self.stop.is_set():
            try:
                if kind=='tcp':
                    c,_=s.accept()
                    with c:
                        c.settimeout(1);d=c.recv(256)
                        if d==self.token: self.counts[name]+=1;c.sendall(d)
                else:
                    d,addr=s.recvfrom(256)
                    if d==self.token: self.counts[name]+=1;s.sendto(d,addr)
            except (OSError,TimeoutError): pass
    def close(self):
        self.stop.set()
        for s in self.sockets: s.close()
        for t in self.threads:t.join(2)
        return all(not t.is_alive() for t in self.threads) and all(s.fileno()==-1 for s in self.sockets)


def private_home_preflight():
    # Do not chmod, inspect contents, or read any runner profile. Metadata-only strict hold.
    require('HOME' in os.environ,'inherited_home_missing')
    home=Path(os.environ['HOME']).resolve(strict=True);st=home.stat()
    require(stat.S_ISDIR(st.st_mode) and st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)&7==0,
            'runner_home_other_traversal_not_denied')
    if 'CODEX_HOME' in os.environ:
        p=Path(os.environ['CODEX_HOME']).resolve(strict=True)
        require(p==home or home in p.parents,'codex_home_not_under_protected_runner_home')
    return {'runnerHomeOwnerMatches':True,'runnerHomeOtherAccessBitsZero':True,
            'codexHomeAbsentOrUnderProtectedHome':True,'contentsRead':False}


def verify_code(code,pins):
    for name,digest in pins['code'].items():
        require(name in CODE and not (code/name).is_symlink() and sha(code/name)==digest,'code_hash_mismatch')
    require(set(pins['code'])==set(CODE),'code_set_mismatch')


def root_phase(config):
    require(sys.platform=='darwin' and os.geteuid()==0,'root_phase_host_required')
    cfg=json.loads(config.read_text());root=Path(cfg['root']);code=root/'code';raw=root/'root-raw'
    hosted_guard(cfg['hostedContext'],sys.platform,platform.release(),platform.machine(),cfg['runnerUid'])
    require(os.environ.get('SUDO_UID')==str(cfg['runnerUid']),'owned_sudo_runner_identity_required')
    require(root.parent==Path('/private/tmp') and root.name=='network-kernel-groups-v1-'+cfg['runId']+'-1','owned_root_mismatch')
    require(config==root/'runner-private'/'root-config.json' and not config.is_symlink(),'config_path_mismatch')
    require(root.stat().st_uid==cfg['runnerUid'] and stat.S_IMODE(root.stat().st_mode)==0o755,'root_identity_mismatch')
    verify_code(code,cfg['pins']);require(sha(cfg['python'])==cfg['pythonSha256'],'python_hash_changed');raw.mkdir(mode=0o700)
    # All executable inputs become root-owned, immutable to both measurement UID and runner phase.
    os.chown(code,0,0);os.chmod(code,0o755)
    for name in CODE:os.chown(code/name,0,0);os.chmod(code/name,0o444)
    uid=60000+int(cfg['runId'])%4000;gid=uid;name='_ncap'+cfg['runId'];anchor='com.apple/codex.network.'+cfg['runId']
    rules=root/'rules.pf';rules.write_text(scoped_rules(uid));os.chmod(rules,0o600)
    calls=Calls(code,raw,root,cfg['env']);created=[];uuids={};token=None;anchor_loaded=False;echo=None;runtime=None
    fixture={};counter_delta={};root_positive=False;error=None;account_observations={}
    cleanup={'listenersClosed':True,'measurementUidNoProcesses':False,'runtimeRemoved':True,
             'ownedAnchorEmpty':False,'ownedPfReferenceReleased':False,'ownedUserRemoved':False,'ownedGroupRemoved':False,
             'mainRulesUnchanged':False,'allRecordedGroupsGone':False}
    pf_before=None
    def pf(label,tail,**kw):
        argv=['/sbin/pfctl',*tail];require(pf_command_allowed(argv,anchor,rules,token),'unscoped_pf_command_forbidden')
        return calls.run(label,argv,**kw)
    def ds(label,tail,**kw):return calls.run(label,['/usr/bin/dscl','.',*tail],**kw)
    try:
        import pwd,grp
        for lookup,key in [(pwd.getpwuid,uid),(pwd.getpwnam,name),(grp.getgrgid,gid),(grp.getgrnam,name)]:
            try:lookup(key);raise RuntimeError('proposed_account_preexists')
            except KeyError:pass
        pf_before=pf('pf-main-before',['-sr'])
        require(re.search(r'^anchor "com\.apple/\*"',pf_before,re.M) is not None,'existing_apple_anchor_hook_absent')
        require(pf('pf-owned-before',['-a',anchor,'-sr']).strip()=='','owned_anchor_preexists')
        pf('pf-syntax',['-a',anchor,'-nf',str(rules)])
        for kind in ('Groups','Users'):
            record='/'+kind+'/'+name;ident=str(uuid.uuid4()).upper();uuids[kind]=ident
            # An exclusive absent record was proved above; journal before each mutation.
            created.append(kind);ds('create-'+kind,['-create',record])
            ds('uuid-'+kind,['-create',record,'GeneratedUID',ident])
            ds('gid-'+kind,['-create',record,'PrimaryGroupID',str(gid)])
        user='/Users/'+name
        for key,value in [('UniqueID',str(uid)),('UserShell','/usr/bin/false'),('NFSHomeDirectory',str(root/'user-home')),
                          ('Password','*'),('IsHidden','1')]:
            ds('user-'+key,['-create',user,key,value])
        home=root/'user-home';home.mkdir(mode=0o700);os.chown(home,uid,gid)
        require(pwd.getpwuid(uid).pw_name==name and pwd.getpwuid(uid).pw_gid==gid,'created_account_identity_mismatch')
        runtime=Path('/var/tmp')/('corbanu-credential-canary-uidpf-'+cfg['runId'])
        runtime.mkdir(mode=0o700);os.chown(runtime,uid,gid)
        inner=home/'inner-write';inner.write_bytes(b'SYNTHETIC_INNER_ONLY_SENTINEL\n');os.chmod(inner,0o600);os.chown(inner,uid,gid)
        addr=calls.run('owned-ipv4',['/usr/sbin/ipconfig','getifaddr','en0']).strip();ip=ipaddress.ip_address(addr)
        require(ip.version==4 and not(ip.is_loopback or ip.is_multicast or ip.is_unspecified),'nonloopback_owned_ipv4_unavailable')
        echo=Echoes(addr,cfg['nonce']).start()
        mf=load('measurement_helpers',code/'measurement-fixture-v2.py')
        for label,ep in echo.endpoints.items():
            require(mf.exchange(ep['kind'],ep['host'],ep['port'],cfg['nonce'])['echo'],'root_positive_before_'+label)
        anchor_loaded=True  # Record the owned mutation attempt before invoking PF.
        pf('pf-owned-load',['-a',anchor,'-f',str(rules)])
        pf('pf-enable',['-E']);token=enable_token((raw/'pf-enable.stdout').read_text()+(raw/'pf-enable.stderr').read_text())
        before=parse_labels(pf('pf-labels-before',['-a',anchor,'-s','labels']))
        cc={k:cfg[k] for k in ('runnerUid','runnerSentinel','runnerUnix','machName','preserved')}
        cc.update(uid=uid,gid=gid,userHome=str(home),runtime=str(runtime),innerSentinel=str(inner),
                  token=cfg['nonce'],endpoints=echo.endpoints,env=cfg['env'],python=cfg['python'],pythonSha256=cfg['pythonSha256'],pins=cfg['pins'])
        childcfg=home/'fixture.json';write(childcfg,cc);os.chmod(childcfg,0o400);os.chown(childcfg,uid,gid)
        seen_before=dict(echo.counts)
        try:
            calls.run('measurement',['/bin/launchctl','asuser',str(uid),cfg['python'],'-I','-B',str(code/'capability-controller-v8.py'),
                                     '--drop-child',str(childcfg)],allowed=(0,2),seconds=35)
        finally:
            # This exact output is always captured even on capability failure.
            if (raw/'measurement.stdout').exists():
                text=(raw/'measurement.stdout').read_text()
                try: fixture=json.loads(text)
                except (ValueError,TypeError): fixture={'status':'HOLD_INVALID_FIXTURE_OUTPUT'}
        after=parse_labels(pf('pf-labels-after',['-a',anchor,'-s','labels']))
        counter_delta=packet_deltas(before,after)
        require(all(echo.counts[k]==seen_before[k] for k in ('deny_tcp4','deny_udp4')),'denied_endpoint_received_measurement')
        for k in ('deny_tcp4','deny_udp4'):
            ep=echo.endpoints[k];require(mf.exchange(ep['kind'],ep['host'],ep['port'],cfg['nonce'])['echo'],'root_positive_after_'+k)
        root_positive=True
    except BaseException as exc:error=str(exc) if isinstance(exc,RuntimeError) else type(exc).__name__
    finally:
        # Cleanup is scoped by exact numeric UID / generated record UUID / PF token / owned paths.
        if echo:cleanup['listenersClosed']=echo.close()
        try:
            calls.run('uid-processes',['/usr/bin/pgrep','-u',str(uid)],allowed=(1,),cleanup=True)
            cleanup['measurementUidNoProcesses']=True
        except BaseException:pass
        if runtime:
            try:
                require(cleanup['measurementUidNoProcesses'],'uid_process_still_present')
                require(runtime.resolve().parent==Path('/private/var/tmp') and runtime.stat().st_uid==uid,'runtime_identity_mismatch')
                # Child cleans each Unix fixture itself. Never recursive delete on unexpected content.
                runtime.rmdir();cleanup['runtimeRemoved']=True
            except BaseException:cleanup['runtimeRemoved']=False
        # Isolation must outlive every owned UID process, including an uncertain observation.
        if cleanup['measurementUidNoProcesses']:
            try:
                if anchor_loaded:pf('pf-owned-clear',['-a',anchor,'-F','rules'],cleanup=True)
                cleanup['ownedAnchorEmpty']=pf('pf-owned-after',['-a',anchor,'-sr'],cleanup=True).strip()==''
            except BaseException:pass
            if token is None and (raw/'pf-enable.stdout').exists():
                try:token=enable_token((raw/'pf-enable.stdout').read_text()+(raw/'pf-enable.stderr').read_text())
                except BaseException:pass  # Never guess or release someone else's reference.
            try:
                if token:pf('pf-release',['-X',token],cleanup=True);cleanup['ownedPfReferenceReleased']=True
                else:cleanup['ownedPfReferenceReleased']=not anchor_loaded
            except BaseException:pass
        # Otherwise retain anchor/reference/account. Disposable VM destruction is the final boundary.
        try:cleanup['mainRulesUnchanged']=pf_before is not None and pf('pf-main-after',['-sr'],cleanup=True)==pf_before
        except BaseException:pass
        for kind,key in [('Users','ownedUserRemoved'),('Groups','ownedGroupRemoved')]:
            phase='not-started'
            try:
                if kind not in created:
                    cleanup[key]=True;account_observations[kind]={'state':'not-created','removed':True};continue
                phase='process-absence'
                require(cleanup['measurementUidNoProcesses'],'uid_process_still_present')
                record='/'+kind+'/'+name
                phase='uuid-check'
                actual=ds('check-delete-'+kind,['-read',record,'GeneratedUID'],cleanup=True).strip()
                require(actual=='GeneratedUID: '+uuids[kind],'account_uuid_changed_or_incomplete')
                phase='numeric-check'
                numeric=ds('numeric-delete-'+kind,['-read',record,'UniqueID' if kind=='Users' else 'PrimaryGroupID'],cleanup=True).strip()
                require(numeric==('UniqueID: ' if kind=='Users' else 'PrimaryGroupID: ')+str(uid),'account_numeric_identity_changed')
                phase='delete'
                ds('delete-'+kind,['-delete',record],cleanup=True)
                # A missing exact record after deletion is verified via scoped libc directory lookup.
                phase='absence-lookup'
                owned={'name':name,'uuid':uuids[kind],'uid':uid,'gid':gid}
                observation=observe_account_absence(pwd.getpwnam if kind=='Users' else grp.getgrnam,
                                                    name,owned if kind=='Users' else None)
                account_observations[kind]={'libc':observation};cleanup[key]=False
                if kind=='Users':
                    phase='directory-absence'
                    account=load('account_observation',code/'account-observation-v1.py')
                    calls.run('read-deleted-Users',['/usr/bin/dscl','-plist','.','-read',record,
                              'RecordName','GeneratedUID','UniqueID','PrimaryGroupID'],
                              allowed=(0,56),seconds=10,cleanup=True,capture_limit=16384)
                    directory=account.classify_directory((raw/'read-deleted-Users.stdout').read_bytes(),
                              (raw/'read-deleted-Users.stderr').read_bytes(),calls.rows[-1],owned)
                    account_observations[kind]['directory']=directory
                    cleanup[key]=account.removed(observation,directory)
                else:
                    cleanup[key]=observation['removed']
            except BaseException as exc:
                account_observations.setdefault(kind,{})['failure']={
                    'state':'cleanup-error','phase':phase,'removed':False,'exceptionType':type(exc).__name__}
        uid_process_observation=None
        if not cleanup['measurementUidNoProcesses']:
            # Observe only after existing cleanup decisions. Never retry absence,
            # kill a process, or release retained isolation based on this snapshot.
            uid_process_observation=observe_owned_uid_processes(calls,raw,uid)
        cleanup['allRecordedGroupsGone']=all(r['groupGone'] for r in calls.rows)
        result={'schema':'network-uid-pf-root-phase-v1','status':capability_status(fixture,cleanup,counter_delta,root_positive),
                'error':error,'fixture':fixture,'pfEnforcementRetainedForLiveOrUnknownUid':not cleanup['measurementUidNoProcesses'],'cleanup':cleanup,'accountRemovalObservations':account_observations,'counterDelta':counter_delta,'rootEndpointPositiveAfter':root_positive,
                'uidProcessObservation':uid_process_observation,
                'commands':calls.rows,'productBodiesExecuted':0,'buildInvocations':0,'canaryInvocations':0,'canaryReady':False,
                'limits':['No external traffic probes. Nonloopback denial is same-owned-host IPv4 TCP/UDP plus actual UID PF counters.',
                          'IPv6 external denial is static rule scope only; live positive is ::1.',
                          'Synthetic Mach service separates runner user; it does not qualify all system credential-service APIs.',
                          'UID/PF is a distinct method; it does not clear the original host denial or prove equivalent outer Seatbelt semantics.']}
        if error:result['status']='HOLD_CAPABILITY_INCOMPLETE'
        write(raw/'root-result.json',result)
        for f in raw.iterdir():
            if f.is_file() and not f.is_symlink():os.chown(f,cfg['runnerUid'],cfg['runnerGid']);os.chmod(f,0o600)
        os.chown(raw,cfg['runnerUid'],cfg['runnerGid']);os.chmod(raw,0o700)
    return 0 if result['status']=='SYNTHETIC_CAPABILITY_PASSED_NOT_CANARY_ADMISSION' else 2


def drop_child(config):
    require(sys.platform=='darwin' and os.geteuid()==0,'credential_drop_requires_owned_root_phase')
    cfg=json.loads(config.read_text());code=Path(__file__).resolve().parent
    require(config.parent.name=='user-home' and config.stat().st_uid==cfg['uid'],'child_config_identity_mismatch')
    verify_code(code,cfg['pins']);require(sha(cfg['python'])==cfg['pythonSha256'],'python_hash_changed');require(60000<=cfg['uid']<64000 and cfg['gid']==cfg['uid'],'child_uid_mismatch')
    # asuser changes Mach bootstrap/audit context only. Remove supplementary groups and root permanently.
    os.setgroups([cfg['gid']]);os.setgid(cfg['gid']);os.setuid(cfg['uid'])
    credentials=load('owned_kernel_credentials',code/'kernel-credentials-v1.py')
    observation=credentials.observe(cfg['uid'],cfg['gid'])
    try:
        sys.stderr.write('NETWORK_KERNEL_CREDENTIALS_V1 '+json.dumps(observation,sort_keys=True)+'\n')
        sys.stderr.flush()
    except BaseException:pass  # Reporting never admits a failed credential tuple.
    require(observation['credentialPassed'],'credential_drop_failed')
    os.chdir(cfg['userHome'])
    os.execve(cfg['python'],[cfg['python'],'-I','-B',str(code/'measurement-fixture-v2.py'),'--config',str(config)],cfg['env'])


def main():
    p=argparse.ArgumentParser();p.add_argument('--dispatch',action='store_true');p.add_argument('--pins-sha256')
    p.add_argument('--output',type=Path);p.add_argument('--root-phase',type=Path);p.add_argument('--drop-child',type=Path);a=p.parse_args()
    if a.root_phase:return root_phase(a.root_phase)
    if a.drop_child:return drop_child(a.drop_child)
    require(a.dispatch and a.output and a.pins_sha256,'explicit_dispatch_required')
    hosted_guard(os.environ,sys.platform,platform.release(),platform.machine(),os.getuid())
    here=Path(__file__).resolve().parent;pinsfile=here/'capability-pins-v8.json'
    require(sha(pinsfile)==a.pins_sha256,'pins_digest_mismatch');pins=json.loads(pinsfile.read_text());verify_code(here,pins)
    admission=json.loads((here/'admission-v8.json').read_text())
    require(admission=={'schema':'network-uid-pf-admission-v1','approved':True,'scope':'synthetic-capability-only',
                       'pinsSha256':a.pins_sha256,'canaryApproved':False},'explicit_reviewed_capability_admission_missing')
    output=a.output.resolve();require(output==Path(os.environ['GITHUB_WORKSPACE']).resolve()/'capability-evidence','output_path_mismatch');output.mkdir(mode=0o700);root=None;mach=None;service=None;unix=None;rows=[];report={}
    result={'schema':'network-uid-pf-capability-result-v1','status':'HOLD_CAPABILITY_INCOMPLETE','error':None,
            'primaryFailure':None,'cleanupFailures':[],'reportingFailures':[],
            'canaryReady':False,'productBodiesExecuted':0,'canaryInvocations':0,'buildInvocations':0,'cleanup':{}}
    try:
        result['freeBytesBefore']=shutil.disk_usage('/private/tmp').free
        require(result['freeBytesBefore']>=6*GIB,'initial_capacity_below_6gib')
        result['runnerHomeGate']=private_home_preflight()
        runid=os.environ['GITHUB_RUN_ID'];root=Path('/private/tmp')/('network-kernel-groups-v1-'+runid+'-1');root.mkdir(mode=0o755)
        raw=root/'runner-raw';raw.mkdir(mode=0o700);private=root/'runner-private';private.mkdir(mode=0o700)
        code=root/'code';code.mkdir(mode=0o755)
        for name in CODE:shutil.copyfile(here/name,code/name);os.chmod(code/name,0o444)
        runnerSentinel=private/'sentinel';runnerSentinel.write_bytes(b'SYNTHETIC_RUNNER_PRIVATE\n');os.chmod(runnerSentinel,0o600)
        result['runnerFilePositive']=runnerSentinel.read_bytes()==b'SYNTHETIC_RUNNER_PRIVATE\n'
        unix=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);unix.settimeout(1);unix.bind(str(private/'u.sock'));unix.listen(1)
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as c:
            c.settimeout(1);c.connect(str(private/'u.sock'));accepted,_=unix.accept();accepted.close()
        mach=load('runner_owned_mach',code/'mach-fixture-v2.py');machname='org.codex.synthetic.ncap.'+runid+'.'+uuid.uuid4().hex
        service=mach.OwnedService(machname)
        service.register();result['runnerMachPositive']=True
        cfg={'root':str(root),'runId':runid,'runnerUid':os.getuid(),'runnerGid':os.getgid(),'runnerSentinel':str(runnerSentinel),
             'runnerUnix':str(private/'u.sock'),'machName':machname,'nonce':uuid.uuid4().hex,'python':str(Path(sys.executable).resolve()),
             'hostedContext':{k:os.environ[k] for k in CONTEXT},'env':environment(os.environ),'preserved':{k:[k in os.environ,os.environ.get(k)] for k in PRESERVED},'pins':pins}
        require(Path(cfg['python']).is_file() and not cfg['python'].startswith(str(Path(os.environ['HOME']))+'/'),'python_under_private_runner_home')
        cfg['pythonSha256']=sha(cfg['python'])
        require(Path(cfg['python']).stat().st_uid==0 and Path(cfg['python']).stat().st_mode & 0o022==0,'python_not_root_owned_immutable')
        write(private/'root-config.json',cfg);os.chmod(private/'root-config.json',0o600)
        calls=Calls(code,raw,root,cfg['env'],seconds=360);rows=calls.rows
        calls.run('privileged-capability',['/usr/bin/sudo','-n',cfg['python'],'-I','-B',str(code/'capability-controller-v8.py'),
                                         '--root-phase',str(private/'root-config.json')],allowed=(0,2),seconds=335)
        report=json.loads((root/'root-raw'/'root-result.json').read_text())
        result['rootPhase']=report;result['status']=report['status']
    except BaseException as exc:
        record_failure(result,'primary',str(exc) if isinstance(exc,RuntimeError) else type(exc).__name__)
    finally:
        if unix:
            unix.close()
            try:(root/'runner-private'/'u.sock').unlink();result['cleanup']['runnerUnixClosedRemoved']=True
            except OSError:result['cleanup']['runnerUnixClosedRemoved']=False
        if service is not None:
            try:
                m=service.cleanup();result['cleanup']['runnerMach']=m
                require(m['qualified'] is True,'owned_mach_cleanup_failed')
            except BaseException:record_failure(result,'cleanup','owned_mach_cleanup_failed')
            finally:result['runnerMachLifecycle']=service.snapshot()
        if root:
            try:
                result['cleanup']['runnerSentinelUnchanged']=(root/'runner-private'/'sentinel').read_bytes()==b'SYNTHETIC_RUNNER_PRIVATE\n'
                verify_code(root/'code',pins);result['cleanup']['sourceUnchanged']=True
            except BaseException:record_failure(result,'cleanup','source_or_sentinel_final_check_failed')
        result['commands']=rows;result['cleanup']['runnerGroupsGone']=all(r['groupGone'] for r in rows)
        if result['error'] or not result['cleanup']['runnerGroupsGone'] or not result['cleanup'].get('runnerUnixClosedRemoved') or not result['cleanup'].get('runnerSentinelUnchanged'):result['status']='HOLD_CAPABILITY_INCOMPLETE'
        # Original captures remain local. Every public stream/result uses the same exact-token rule.
        exports=[]
        if root:
            for dirname in ('runner-raw','root-raw'):
                src=root/dirname
                if src.exists():
                    dest=output/dirname;dest.mkdir()
                    try:files=list(src.iterdir())
                    except OSError:
                        record_failure(result,'reporting','owned_capture_inaccessible');continue
                    for f in files:
                        if not f.is_file() or f.is_symlink() or f.suffix not in ('.stdout','.stderr','.json'):continue
                        try:data=f.read_bytes()
                        except OSError:
                            record_failure(result,'reporting','owned_capture_read_failed');continue
                        try:
                            public,projection=public_projection(data,os.environ['GITHUB_RUN_ID'])
                            with (dest/f.name).open('xb') as stream:stream.write(public)
                            exports.append({'path':dirname+'/'+f.name,**projection,'withheld':False})
                        except RuntimeError:
                            withheld={'originalSha256':hashlib.sha256(data).hexdigest(),'originalBytes':len(data),'withheld':True}
                            write(dest/(f.name+'.withheld.json'),withheld);exports.append({'path':dirname+'/'+f.name,**withheld})
                            record_failure(result,'reporting','remaining_private_or_sensitive_stream_withheld')
        original_result=(json.dumps(result,indent=2,sort_keys=True)+'\n').encode()
        if root and (root/'runner-private').is_dir():
            with (root/'runner-private'/'controller-result-original.json').open('xb') as stream:stream.write(original_result)
        try:
            public_result,projection=public_projection(original_result,os.environ['GITHUB_RUN_ID'])
            with (output/'capability-result.json').open('xb') as stream:stream.write(public_result)
            exports.append({'path':'capability-result.json',**projection,'withheld':False})
        except RuntimeError:
            record_failure(result,'reporting','selected_result_projection_held')
            write(output/'capability-result.json',{'schema':'network-uid-pf-capability-result-v1','status':result['status'],
                'error':'selected_result_projection_held','originalSha256':hashlib.sha256(original_result).hexdigest(),
                'canaryReady':False,'productBodiesExecuted':0,'buildInvocations':0,'canaryInvocations':0})
            exports.append({'path':'capability-result.json','originalSha256':hashlib.sha256(original_result).hexdigest(),'withheld':True})
        write(output/'export-manifest-v2.json',{'schema':'network-uid-pf-export-manifest-v2','files':exports,
            'normalization':'Exact owned DS record token only; all other /Users/ paths and sensitive shapes held.',
            'rawConfigsOrEnvironmentExported':False})
    return 0 if result['status']=='SYNTHETIC_CAPABILITY_PASSED_NOT_CANARY_ADMISSION' else 2

if __name__=='__main__':sys.exit(main())
