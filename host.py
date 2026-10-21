#!/usr/bin/env python3
"""Dedicated GitHub Ubuntu VM host controller. Inert without exact admission."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys
import time

from evidence import Hold, need, normalize, normalize_xml

HERE=Path(__file__).resolve().parent
BRANCH='codex/issue1056-mountinfo-linux-v1-20261021'
WORKFLOW='.github/workflows/issue1056-mountinfo-linux-v1.yml'
BASE='3b56e6952e3e85fc0b940ee319b7a19d344a6ff5'
UID=21056


def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        while chunk:=f.read(8*1024*1024):h.update(chunk)
    return h.hexdigest()


def write(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x') as f:json.dump(data,f,indent=2,sort_keys=True);f.write('\n')


def checked(argv,seconds=120,cwd=None):
    p=subprocess.run(argv,cwd=cwd,capture_output=True,timeout=seconds)
    need(p.returncode==0,'host_command_failed_'+Path(argv[0]).name)
    return p.stdout


class Budget:
    # Work may consume at most 140 minutes from host entry. Cleanup/export gets
    # another 5 minutes. The 160-minute job retains 15 minutes for checkout/upload.
    def __init__(self, seconds=8400):self.deadline=time.monotonic()+seconds
    def remaining(self, cap, reserve=0):
        value=int(self.deadline-time.monotonic()-reserve)
        need(value>0,'host_global_deadline')
        return min(cap,value)


def capture_error(result, field, code):
    result[field]=result.get(field) or code
    result['qualified']=False


def finalize_host(result, export, root, worker):
    budget=Budget(300);uid_absent=False
    try:
        if result['uidCreated']:
            for sig in ['TERM','KILL']:
                current=subprocess.run(['pgrep','-u',str(UID)],capture_output=True,timeout=budget.remaining(10))
                if current.returncode==1 and not current.stdout and not current.stderr:uid_absent=True;break
                subprocess.run(['sudo','-n','pkill','-'+sig,'-u',str(UID)],capture_output=True,timeout=budget.remaining(10));time.sleep(2)
            current=subprocess.run(['pgrep','-u',str(UID)],capture_output=True,timeout=budget.remaining(10))
            uid_absent=current.returncode==1 and not current.stdout and not current.stderr
            if not uid_absent:capture_error(result,'cleanupFailure','synthetic_uid_processes_remaining_or_unknown')
    except BaseException as error:capture_error(result,'cleanupFailure','uid_cleanup_'+type(error).__name__)
    try:
        if worker:worker.wait(timeout=budget.remaining(10))
        result['directWorkerReaped']=worker is None or worker.poll() is not None
    except BaseException as error:
        result['directWorkerReaped']=False;capture_error(result,'cleanupFailure','direct_child_'+type(error).__name__)
    result['syntheticUidAbsent']=uid_absent
    result['filesystemRetention']='Synthetic HOME/tmp removed only after confirmed worker cleanup. Sources, targets and caches remain solely on disposable VM. Audited selected raw and normalized evidence plus exact binaries are uploaded separately.'
    # Never put an unaudited copy in the upload directory. This staging path is
    # outside every artifact glob, and remains withheld if any operation fails.
    staging=export.parent/'issue1056-export-staging'
    if root and uid_absent:
        try:
            staging.mkdir(exist_ok=False)
            for name in ['evidence','binaries']:
                src=root/name
                check=subprocess.run(['sudo','-n','test','-d',str(src)],capture_output=True,timeout=budget.remaining(10))
                need(check.returncode in (0,1),'evidence_presence_unknown')
                if check.returncode==1:continue
                destination=staging/('worker-evidence' if name=='evidence' else 'binaries')
                checked(['sudo','-n','cp','-a','--',str(src),str(destination)],seconds=budget.remaining(120))
                checked(['sudo','-n','chown','-R','--no-dereference',str(os.getuid())+':'+str(os.getgid()),str(destination)],seconds=budget.remaining(30))
            audit_staging(staging,export,result,budget)
        except BaseException as error:capture_error(result,'exportFailure','export_'+type(error).__name__)
    wr=export/'worker-evidence/result.json'
    try:
        if wr.is_file():
            data=json.loads(wr.read_text());need(isinstance(data,dict),'worker_result_shape')
            result['workerQualified']=data.get('qualified',False)
            result['workerFailureCode']=data.get('failureCode');result['workerCleanupFailure']=data.get('cleanupFailure')
            result['failureCode']=result['failureCode'] or data.get('failureCode')
            result['qualified']=bool(data.get('qualified') is True and uid_absent and result['directWorkerReaped'] and result.get('workerExitCode')==0 and not result['failureCode'] and not result['cleanupFailure'] and not result.get('exportFailure'))
        else:capture_error(result,'exportFailure','worker_result_missing')
    except BaseException as error:capture_error(result,'exportFailure','worker_result_'+type(error).__name__)


def audit_staging(staging,export,result,budget):
    entries=list(staging.rglob('*'));need(len(entries)<=10000,'export_file_count_bound')
    for path in entries:
        budget.remaining(300)
        relative=path.relative_to(staging)
        try:
            need(not path.is_symlink() and (path.is_file() or path.is_dir()),'unsafe_export_type')
            if path.is_dir():continue
            record={'path':str(relative),'bytes':path.stat().st_size,'sha256':digest(path)}
            if relative.parts[0]=='binaries':
                with path.open('rb') as f:magic=f.read(4)
                need(len(relative.parts)==3 and relative.parts[1] in ('baseline','candidate') and re.fullmatch(r'codex_linux_sandbox-[a-f0-9]+',relative.name) and magic==b'\x7fELF','unsafe_binary_export')
            else:
                need(relative.parts[0]=='worker-evidence' and path.suffix in ('.log','.json','.xml','.txt') and path.stat().st_size<=128*1024*1024,'unsafe_evidence_export')
                if 'raw' in relative.parts:
                    need(len(relative.parts)==4 and relative.parts[2]=='raw' and re.fullmatch('[a-z0-9-]+',relative.parts[1]) and relative.name in ('stdout.log','stderr.log','combined.log','junit.xml'),'unselected_raw_export')
                raw=path.read_bytes();normalize(raw,{})
                if path.suffix=='.xml':normalize_xml(raw,{})
            destination=export/relative;destination.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(path,destination);need(digest(destination)==record['sha256'],'export_copy_hash')
            result['exports'].append(record)
        except BaseException as error:
            # The source remains in non-upload staging. No unsafe bytes are copied.
            capture_error(result,'exportFailure','audit_'+type(error).__name__)
            result.setdefault('withheldExports',[]).append({'path':str(relative),'reason':type(error).__name__})


def emit_result(export,result):
    try:write(export/'host-result.json',result);return True
    except BaseException as error:
        print(json.dumps({'qualified':False,'failureCode':result.get('failureCode'),'cleanupFailure':result.get('cleanupFailure'),'exportFailure':result.get('exportFailure'),'receiptFailure':type(error).__name__}))
        return False


def main():
    export=HERE.parent/'issue1056-evidence';budget=Budget()
    result={'schema':'issue1056-host-result-v1','qualified':False,'failureCode':None,'cleanupFailure':None,'exportFailure':None,'uidCreated':False,'workerStarted':False,'sourceBase':BASE,'exports':[]}; root=None;user=None;worker=None
    try:
        export.mkdir(exist_ok=False)
        result['deadlinePolicy']={'hostWorkSeconds':8400,'cleanupExportSeconds':300,'workflowSeconds':9600,'checkoutUploadMarginSeconds':900}
        admission=json.loads((HERE/'admission.json').read_text());manifest=json.loads((HERE/'packet-manifest.json').read_text())
        need(admission['approved'] is True and re.fullmatch('[a-f0-9]{64}',admission['reviewReceiptSha256']),'packet_not_admitted')
        need(admission['packetManifestSha256']==digest(HERE/'packet-manifest.json'),'admitted_manifest_mismatch')
        for row in manifest['files']:
            p=HERE/row['path'];need(p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(HERE),'packet_path');need(digest(p)==row['sha256'] and p.stat().st_size==row['bytes'],'packet_hash')
        identity={key:os.environ.get(key) for key in ['GITHUB_REPOSITORY','GITHUB_EVENT_NAME','GITHUB_REF','GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_RUN_NUMBER','GITHUB_WORKFLOW_REF','ImageOS','ImageVersion']}
        need(identity['GITHUB_REPOSITORY']=='citadelculture/CorbanuTerminal' and identity['GITHUB_EVENT_NAME']=='push' and identity['GITHUB_REF']=='refs/heads/'+BRANCH,'workflow_route')
        need(identity['GITHUB_RUN_ATTEMPT']=='1' and identity['GITHUB_RUN_NUMBER']=='1','not_first_run_attempt')
        need(re.fullmatch('[0-9]+',identity['GITHUB_RUN_ID'] or '') and re.fullmatch('[a-f0-9]{40}',identity['GITHUB_SHA'] or ''),'run_identity')
        need(identity['GITHUB_WORKFLOW_REF']==identity['GITHUB_REPOSITORY']+'/'+WORKFLOW+'@refs/heads/'+BRANCH,'workflow_identity')
        need(sys.platform=='linux' and os.geteuid()!=0,'host_not_expected_nonroot_linux')
        result['identity']=identity;result['admissionSha256']=digest(HERE/'admission.json');result['packetManifestSha256']=digest(HERE/'packet-manifest.json')
        root=Path('/tmp/issue1056-linux-v1-'+identity['GITHUB_RUN_ID']);root.mkdir(mode=0o755,exist_ok=False)
        need(shutil.disk_usage(root).free>=32*1024**3,'host_admission_below_32GiB')
        write(export/'resource-admission.json',{'freeBytes':shutil.disk_usage(root).free,'minimumBytes':32*1024**3,'continuousBytes':6*1024**3,'buildJobs':2,'devAndTestDebugSymbols':0,'debugAssertions':True,'incremental':0,'targets':'two fresh targets; no compiled artifact reuse','scope':'Disposable VM only; no owner-host reserve change.'})
        budget.remaining(120)
        upstream=HERE.parent/'upstream';need(checked(['git','rev-parse','HEAD'],cwd=upstream).decode().strip()==BASE,'public_base_identity')
        need(not checked(['git','status','--porcelain=v1','--untracked-files=all'],cwd=upstream),'unclean_public_checkout')
        names=checked(['git','ls-files','-z'],cwd=upstream).decode().split('\0');names=[n for n in names if n]
        need(len(names)<100000,'source_count')
        for lane in ['baseline','candidate']:
            source=root/lane;source.mkdir()
            for name in names:
                budget.remaining(120)
                relative=Path(name);need(not relative.is_absolute() and '..' not in relative.parts,'source_path')
                src=upstream/relative;dst=source/relative;dst.parent.mkdir(parents=True,exist_ok=True)
                if src.is_symlink():
                    need(src.resolve().is_relative_to(upstream.resolve()),'public_source_symlink_escape');dst.symlink_to(os.readlink(src))
                else:need(src.is_file(),'public_source_nonfile');shutil.copy2(src,dst)
        write(root/'base-source-files.json',names)
        shutil.copytree(HERE,root/'control',ignore=shutil.ignore_patterns('.git','__pycache__'))
        # System prerequisites are signed Ubuntu packages. Capture exact installed
        # versions; no user Cargo/Git configuration or credential directories copy.
        commands=[['sudo','-n','apt-get','update','-y'],['sudo','-n','env','DEBIAN_FRONTEND=noninteractive','apt-get','install','-y','--no-install-recommends','build-essential','pkg-config','libcap-dev','libssl-dev','clang','cmake','ninja-build','git','python3','xz-utils','ca-certificates']]
        for number,argv in enumerate(commands):
            start=time.monotonic();p=subprocess.run(argv,capture_output=True,timeout=budget.remaining(600));raw=p.stdout+b'\n'+p.stderr
            need(len(raw)<=8*1024*1024,'system_provision_log_bound');public=normalize(raw,{str(root):'<CAMPAIGN>',str(HERE.parent):'<WORKSPACE>'});(export/f'system-provision-{number}.log').write_bytes(public)
            write(export/f'system-provision-{number}.json',{'argv':argv,'exitCode':p.returncode,'elapsedSeconds':round(time.monotonic()-start,3),'rawSha256':hashlib.sha256(raw).hexdigest(),'rawBytes':len(raw),'normalizedSha256':hashlib.sha256(public).hexdigest(),'normalizedBytes':len(public)})
            need(p.returncode==0,'system_prerequisite_failed')
        versions=checked(['dpkg-query','-W','-f=${Package}\t${Version}\n','build-essential','pkg-config','libcap-dev','libssl-dev','clang','cmake','ninja-build','git','python3','xz-utils','ca-certificates'])
        (export/'system-package-versions.txt').write_bytes(versions)
        try:pwd.getpwuid(UID);raise RuntimeError('synthetic_uid_already_exists')
        except KeyError:pass
        absent=subprocess.run(['pgrep','-u',str(UID)],capture_output=True);need(absent.returncode==1 and not absent.stdout and not absent.stderr,'synthetic_uid_has_processes')
        user='issue1056-'+identity['GITHUB_RUN_ID'];checked(['sudo','-n','useradd','--no-create-home','--user-group','--uid',str(UID),'--shell','/usr/sbin/nologin',user]);result['uidCreated']=True
        checked(['sudo','-n','chown','-R','--no-dereference',user+':'+user,str(root)]);checked(['sudo','-n','chmod','0700',str(root)])
        env={'PATH':'/usr/bin:/bin','HOME':str(root),'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'}
        env.update({key:os.environ[key] for key in ['CODEX_SANDBOX','CODEX_SANDBOX_NETWORK_DISABLED'] if key in os.environ})
        worker_budget=budget.remaining(8100);result['workerBudgetSeconds']=worker_budget
        argv=['sudo','-n','-u',user,'/usr/bin/env','-i',*[k+'='+v for k,v in env.items()],'/usr/bin/python3',str(root/'control/worker.py'),'--root',str(root),'--control',str(root/'control'),'--budget-seconds',str(worker_budget)]
        worker=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True);result['workerStarted']=True
        try:stdout,stderr=worker.communicate(timeout=budget.remaining(worker_budget))
        except subprocess.TimeoutExpired:result['failureCode']='host_worker_deadline';stdout=b'';stderr=b''
        result['workerExitCode']=worker.poll()
        # Unexpected controller startup diagnostics are withheld from publication;
        # hashes/counts remain factual and do not conceal the primary failure.
        result['workerStartupCapture']={'stdoutBytes':len(stdout),'stdoutSha256':hashlib.sha256(stdout).hexdigest(),'stderrBytes':len(stderr),'stderrSha256':hashlib.sha256(stderr).hexdigest(),'rawRetainedOnRunnerOnly':True}
        if stdout or stderr:result['failureCode']=result['failureCode'] or 'unexpected_worker_startup_output'
    except BaseException as error:
        result['failureCode']=result['failureCode'] or (str(error) if isinstance(error,RuntimeError) else type(error).__name__)
    finally:
        try:finalize_host(result,export,root,worker)
        except BaseException as error:capture_error(result,'cleanupFailure','finalization_'+type(error).__name__)
        if not emit_result(export,result):result['qualified']=False
    return 0 if result['qualified'] else 1


if __name__=='__main__':sys.exit(main())
