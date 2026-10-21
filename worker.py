#!/usr/bin/env python3
"""One-shot dedicated-VM library qualification. No native credential claim."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import platform
import resource
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time
import tomllib
import urllib.request

from evidence import Hold, need, sha, normalize, normalize_xml, classify

GIB = 1024**3
CODEX_MARKERS = ('CODEX_SANDBOX', 'CODEX_SANDBOX_NETWORK_DISABLED')


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as handle:
        json.dump(value, handle, indent=2, sort_keys=True); handle.write('\n')


def file_record(path):
    h = hashlib.sha256()
    with path.open('rb') as handle:
        while data := handle.read(8*1024*1024): h.update(data)
    return {'bytes': path.stat().st_size, 'sha256': h.hexdigest()}


def owned_processes():
    found = []
    for item in Path('/proc').iterdir():
        if not item.name.isdigit() or int(item.name) == os.getpid(): continue
        try:
            if item.stat().st_uid == os.getuid():
                fields = (item/'stat').read_text().rsplit(')', 1)[1].split()
                found.append((int(item.name), fields[19]))
        except FileNotFoundError: pass
    return found


def clean_owned():
    signals = []; errors = []
    for sig, duration in [(signal.SIGTERM, 3), (signal.SIGKILL, 3)]:
        for pid, birth in owned_processes():
            try:
                p = Path('/proc')/str(pid)
                if p.stat().st_uid == os.getuid() and p.joinpath('stat').read_text().rsplit(')',1)[1].split()[19] == birth:
                    os.kill(pid, sig); signals.append({'pid':pid,'signal':sig.name})
            except ProcessLookupError: pass
            except FileNotFoundError: pass
            except OSError as error: errors.append(type(error).__name__)
        end = time.monotonic()+duration
        while time.monotonic()<end:
            try:
                while os.waitpid(-1, os.WNOHANG)[0]: pass
            except ChildProcessError: pass
            if not owned_processes(): break
            time.sleep(.05)
    remaining = owned_processes()
    return {'signals':signals,'errors':errors,'remaining':[pid for pid,_ in remaining],'ownedUidGoneExceptController':not remaining and not errors}


def safe_extract(archive, destination):
    total = 0; count = 0
    with tarfile.open(archive, 'r:*') as tar:
        for member in tar:
            count += 1; total += member.size
            need(count <= 300000 and total <= 10*GIB, 'tool_archive_bound')
            name = Path(member.name)
            need(not name.is_absolute() and '..' not in name.parts, 'archive_path')
            need(member.isfile() or member.isdir() or member.issym() or member.islnk(), 'archive_special_file')
            if member.issym() or member.islnk():
                target = (destination/name.parent/member.linkname).resolve() if member.issym() else (destination/member.linkname).resolve()
                need(target.is_relative_to(destination.resolve()), 'archive_link_escape')
        tar.extractall(destination, filter='data')


class Campaign:
    def __init__(self, root, control, budget_seconds):
        self.root=root; self.control=control; self.output=root/'evidence'; self.output.mkdir()
        self.raw=root/'raw'; self.raw.mkdir(); self.rows=[]; need(1 <= budget_seconds <= 8100, 'worker_budget'); self.deadline=time.monotonic()+budget_seconds; self.budget_seconds=budget_seconds
        self.pins=json.loads((control/'source-pins.json').read_text())
        self.toolpins=json.loads((control/'tool-pins.json').read_text())
        self.tools=root/'tools'; self.tools.mkdir(); self.tools.joinpath('bin').mkdir()
        self.env={'PATH':str(self.tools/'bin')+':/usr/bin:/bin','HOME':str(root/'home'),'TMPDIR':str(root/'tmp'),'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','TERM':'dumb','NO_COLOR':'1','CARGO_TERM_COLOR':'never','CARGO_HOME':str(root/'cargo-home'),'CARGO_BUILD_JOBS':'2','CARGO_INCREMENTAL':'0','CARGO_PROFILE_DEV_DEBUG':'0','CARGO_PROFILE_TEST_DEBUG':'0','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':str(root/'empty.gitconfig'),'GIT_TERMINAL_PROMPT':'0','GIT_CONFIG_COUNT':'1','GIT_CONFIG_KEY_0':'credential.helper','GIT_CONFIG_VALUE_0':'','GIT_SSH_COMMAND':'false','UV_CACHE_DIR':str(root/'uv-cache'),'UV_PYTHON_DOWNLOADS':'never','UV_PYTHON':'/usr/bin/python3','DOTSLASH_CACHE_DIR':str(root/'dotslash-cache'),'RUST_BACKTRACE':'0'}
        self.markers={key:os.environ[key] for key in CODEX_MARKERS if key in os.environ}
        self.env.update(self.markers)
        for p in ('home','tmp','cargo-home','uv-cache','dotslash-cache','metadata-target','binaries'):(root/p).mkdir(mode=0o700)
        (root/'empty.gitconfig').write_text(''); (root/'home'/'.netrc').write_text('')
        (root/'cargo-home'/'config.toml').write_text('[net]\ngit-fetch-with-cli = true\n')
        self.env['CARGO_TARGET_DIR']=str(root/'metadata-target')
        self.replacements={str(root):'<CAMPAIGN>',str(control):'<CONTROL>'}
        write(self.output/'identity.json',{'platform':sys.platform,'uid':os.getuid(),'euid':os.geteuid(),'gid':os.getgid(),'egid':os.getegid(),'sandboxMarkers':self.markers,'ordinaryDebug':True,'operatorCredentialsForwarded':False})
        need(sys.platform=='linux' and platform.machine()=='x86_64' and os.getuid()==os.geteuid()==21056 and os.getgid()!=0 and os.getegid()!=0,'required_fresh_nonroot_identity')
        need(not owned_processes(),'owned_uid_not_exclusive')
        need(ctypes.CDLL(None).prctl(36,1,0,0,0)==0,'subreaper_unavailable')
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        memory={line.split(':')[0]:int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith(('MemTotal:','MemAvailable:'))}
        write(self.output/'memory-admission.json',{'observed':memory,'minimumTotalBytes':7*GIB,'continuousAvailableBytes':256*1024**2})
        need(memory['MemTotal']>=7*GIB,'disposable_memory_admission')
        self.initial_space=self.free(); need(self.initial_space>=32*GIB,'disposable_admission_below_32GiB')

    def free(self): return shutil.disk_usage(self.root).free

    def run(self, stage, argv, cwd, seconds, env=None):
        need(time.monotonic()<self.deadline,'campaign_deadline'); need(self.free()>=6*GIB,'disposable_reserve_before_phase')
        stage_raw=self.raw/stage; stage_raw.mkdir(); started=time.monotonic(); phase_env=dict(self.env); phase_env.update(env or {})
        need({k:phase_env[k] for k in CODEX_MARKERS if k in phase_env}==self.markers,'sandbox_marker_changed')
        paths={key:stage_raw/(key+'.log') for key in ['stdout','stderr','combined']}; handles={key:p.open('wb') for key,p in paths.items()}
        row={'stage':stage,'argv':[str(v).replace(str(self.root),'<CAMPAIGN>') for v in argv],'cwd':str(cwd).replace(str(self.root),'<CAMPAIGN>'),'deadlineSeconds':seconds,'freeBefore':self.free(),'target':phase_env.get('CARGO_TARGET_DIR','').replace(str(self.root),'<CAMPAIGN>'),'exitCode':None,'failureCode':None,'cleanupFailure':None}; proc=None; selected=selectors.DefaultSelector(); total=0
        try:
            proc=subprocess.Popen(argv,cwd=cwd,env=phase_env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            for label,stream in [('stdout',proc.stdout),('stderr',proc.stderr)]:os.set_blocking(stream.fileno(),False);selected.register(stream,selectors.EVENT_READ,label)
            while selected.get_map() or proc.poll() is None:
                if time.monotonic()-started>seconds or time.monotonic()>self.deadline:raise Hold('phase_deadline')
                if self.free()<6*GIB:raise Hold('disposable_free_reserve')
                available=next(int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:'))
                if available<256*1024**2:raise Hold('disposable_memory_reserve')
                for event,_ in selected.select(.2):
                    chunk=os.read(event.fd,65536)
                    if not chunk:selected.unregister(event.fileobj);event.fileobj.close();continue
                    total+=len(chunk);need(total<=64*1024*1024,'capture_bound')
                    handles[event.data].write(chunk);handles['combined'].write(chunk)
            row['exitCode']=proc.wait(timeout=5)
        except BaseException as error:
            row['failureCode']=str(error) if isinstance(error,Hold) else type(error).__name__
        finally:
            try:selected.close()
            except BaseException as error:row['cleanupFailure']='selector_close_'+type(error).__name__
            try:
                self.finish_process(proc,row)
            except BaseException as error:row['cleanupFailure']=row['cleanupFailure'] or 'process_cleanup_'+type(error).__name__
            for handle in handles.values():
                try:handle.close()
                except BaseException as error:row['failureCode']=row['failureCode'] or 'capture_close_'+type(error).__name__
            try:
                cleanup=clean_owned();row['cleanup']=cleanup
                if not cleanup['ownedUidGoneExceptController']:row['cleanupFailure']=row['cleanupFailure'] or 'owned_cleanup_incomplete'
            except BaseException as error:row['cleanupFailure']=row['cleanupFailure'] or 'owned_cleanup_'+type(error).__name__
            row['directChildReaped']=proc is None or proc.poll() is not None
            if not row['directChildReaped']:row['cleanupFailure']=row['cleanupFailure'] or 'direct_child_not_reaped'
            row['elapsedSeconds']=round(time.monotonic()-started,3);row['streams']={}
            try:row['freeAfter']=self.free()
            except BaseException as error:row['failureCode']=row['failureCode'] or 'resource_read_'+type(error).__name__
            try:self.retain_streams(stage,paths,row)
            except BaseException as error:row['failureCode']=row['failureCode'] or 'evidence_retention_'+type(error).__name__
            self.rows.append(row)
            try:write(self.output/stage/'result.json',row)
            except BaseException as error:row['failureCode']=row['failureCode'] or 'phase_receipt_'+type(error).__name__
        need(not row['failureCode'] and not row['cleanupFailure'], 'phase_'+stage+'_held')
        return row

    def finish_process(self, proc, row):
            if proc and proc.poll() is None:
                try:os.killpg(proc.pid,signal.SIGTERM)
                except ProcessLookupError:pass
                try:proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    try:os.killpg(proc.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    try:proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:row['cleanupFailure']='direct_child_not_reaped'
    def retain_streams(self,stage,paths,row):
        stage_out=self.output/stage;stage_out.mkdir(exist_ok=True)
        for label,path in paths.items():
            record={'captureTruncated':row['failureCode']=='capture_bound'};row['streams'][label]=record
            try:
                raw=path.read_bytes();record.update(rawBytes=len(raw),rawSha256=sha(raw),rawRetainedDurably=False)
                # Only these selected credential-free command captures are eligible.
                # Audit the unmodified bytes independently before making a durable copy.
                normalize(raw,{})
                public=normalize(raw,self.replacements)
                raw_dir=stage_out/'raw';raw_dir.mkdir(exist_ok=True)
                (raw_dir/(label+'.log')).write_bytes(raw)
                (stage_out/(label+'.log')).write_bytes(public)
                record.update(rawRetainedDurably=True,rawArtifactPath=stage+'/raw/'+label+'.log',publicBytes=len(public),publicSha256=sha(public))
            except BaseException as error:
                record['withheld']=True;row.setdefault('normalizationFailure',type(error).__name__);row['failureCode']=row['failureCode'] or 'diagnostic_retention_hold'

    def ok(self,stage,argv,cwd,seconds,env=None):
        row=self.run(stage,argv,cwd,seconds,env);need(row['exitCode']==0,stage+'_nonzero');return row

    def download(self, entry):
        need(entry['url'].startswith('https://') and re.fullmatch('[a-f0-9]{64}',entry['sha256']),'download_pin')
        target=self.root/'downloads'/entry['name'];target.parent.mkdir(exist_ok=True);need(not target.exists(),'download_repeated')
        started=time.monotonic();size=0;h=hashlib.sha256()
        try:
            with urllib.request.urlopen(entry['url'],timeout=30) as response,target.open('xb') as out:
                while data:=response.read(1024*1024):
                    size+=len(data);need(size<=2*GIB and time.monotonic()-started<600 and time.monotonic()<self.deadline,'download_bound');need(self.free()>=6*GIB,'download_space');h.update(data);out.write(data)
            need(h.hexdigest()==entry['sha256'],'download_hash_mismatch')
            if entry.get('bytes') is not None:need(size==entry['bytes'],'download_size_mismatch')
        finally:
            write(self.output/('download-'+entry['name']+'.json'),{'name':entry['name'],'url':entry['url'],'bytes':size,'actualSha256':h.hexdigest(),'expectedSha256':entry['sha256'],'completeAndVerified':target.exists() and h.hexdigest()==entry['sha256']})
        return target

    def provision(self):
        for entry in self.toolpins['downloads']:
            archive=self.download(entry);extract=self.root/'unpacked'/entry['name'];extract.mkdir(parents=True)
            if entry['kind']=='raw':
                destination=self.tools/'bin'/entry['executable'];shutil.copyfile(archive,destination);destination.chmod(0o755)
            else:
                safe_extract(archive,extract)
                if entry['kind']=='rust-component':
                    script=extract/entry['root']/'install.sh';need(script.is_file() and not script.is_symlink(),'rust_installer_missing')
                    need((extract/entry['root']/'components').read_text().strip()==entry['component_file_must_equal'],'rust_component_identity')
                    self.ok('install-'+entry['name'],['/bin/sh',str(script),'--prefix='+str(self.tools),'--disable-ldconfig',*entry.get('installArgs',[])],extract,600)
                else:
                    executable=entry['executable'];source=extract/entry['root']/entry['member']
                    matches=[x for x in extract.rglob(executable) if x.is_file() and not x.is_symlink()]
                    need(len(matches)==1 and matches[0]==source and source.is_file(),'tool_member_missing_or_ambiguous')
                    shutil.copyfile(source,self.tools/'bin'/executable);(self.tools/'bin'/executable).chmod(0o755)
            shutil.rmtree(extract);archive.unlink()
        self.env.update(RUSTC=str(self.tools/'bin/rustc'),RUSTDOC=str(self.tools/'bin/rustdoc'))
        need((self.tools/'lib/rustlib/src/rust/library').is_dir(),'rust_source_missing')
        for executable in ['rustc','cargo','rustfmt','cargo-fmt','cargo-clippy']:
            need(Path(shutil.which(executable,path=self.env['PATH'])).resolve().is_relative_to(self.tools/'bin'),'tool_path_outside_owned_prefix')
        self.ok('rust-sysroot',['rustc','--print','sysroot'],self.root,60)
        need((self.raw/'rust-sysroot/stdout.log').read_text().strip()==str(self.tools),'rust_sysroot')
        for tool,args,expected in [('rustc',['--version'],'1.99.1'),('cargo',['--version'],'1.99.1'),('rustfmt',['--version'],'rustfmt'),('cargo-clippy',['--version'],'clippy'),('just',['--version'],'1.58.0'),('cargo-nextest',['nextest','--version'],'0.9.146'),('uv',['--version'],'0.11.3'),('dotslash',['--version'],'0.5.9')]:
            self.ok('version-'+tool,[tool,*args],self.root,60);text=(self.output/('version-'+tool)/'combined.log').read_text();need(expected in text,'tool_version_'+tool)
        write(self.output/'tool-binary-hashes.json',{name:file_record(self.tools/'bin'/name) for name in ['rustc','cargo','rustfmt','cargo-clippy','just','cargo-nextest','uv','dotslash']})

    def snapshot(self, source, names):
        return {name:file_record(source/name) for name in names}

    def verify_tree(self,source,lane):
        for name,expected in {**self.pins['inputs'],**self.pins['trees'][lane]}.items():need(file_record(source/name)==expected,'source_pin_'+name)

    def metadata_guard(self):
        entries=[]
        for p in (self.root/'metadata-target').rglob('*'):
            need(p.is_file() and not p.is_symlink(),'metadata_target_nonfile')
            need(p.relative_to(self.root/'metadata-target').as_posix()=='.rustc_info.json','metadata_target_compiled_output')
            entries.append({'path':'.rustc_info.json',**file_record(p)})
        write(self.output/'metadata-target-inventory.json',{'entries':entries,'compiledOutputsAllowed':False,'qualificationTargetSeparate':True})

    def prepare_sources(self):
        names=json.loads((self.root/'base-source-files.json').read_text());write(self.output/'base-source-files.json',names)
        for lane,patch in [('baseline','instrumented-baseline-v1.patch'),('candidate','complete-v1.patch')]:
            source=self.root/lane
            self.ok(lane+'-git-init',['git','init','-q'],source,60)
            self.ok(lane+'-git-index',['git','add','--all'],source,120)
            self.verify_tree(source,'source-main')
            self.ok(lane+'-patch',['git','apply','--check',str(self.control/'payload'/patch)],source,60)
            self.ok(lane+'-apply',['git','apply',str(self.control/'payload'/patch)],source,60)
            self.verify_tree(source,'instrumented-baseline-v1' if lane=='baseline' else 'candidate-v1')
        candidate=self.root/'candidate'
        lock=tomllib.loads((candidate/'codex-rs/Cargo.lock').read_text())
        sources=sorted({package['source'] for package in lock['package'] if 'source' in package})
        need(sources==self.pins['publicCargoSources'],'public_dependency_source_changed')
        self.ok('cargo-fetch',['cargo','fetch','--locked','--target','x86_64-unknown-linux-gnu'],candidate/'codex-rs',1500)
        for project,extra in [('scripts',[]),('sdk/python',['--only-group','format'])]:
            self.ok('acquire-uv-'+project.replace('/','-'),['uv','sync','--frozen','--project',project,*extra],candidate,600)
        self.ok('acquire-buildifier',['dotslash',str(candidate/'tools/buildifier'),'--version'],candidate,300)
        offline={'CARGO_NET_OFFLINE':'true','UV_OFFLINE':'true'}
        row=self.ok('offline-metadata',['cargo','metadata','--locked','--offline','--format-version','1','--filter-platform','x86_64-unknown-linux-gnu'],candidate/'codex-rs',300,offline)
        metadata=json.loads((self.raw/'offline-metadata/stdout.log').read_text());packages={p['id']:p for p in metadata['packages']};nodes={n['id']:n for n in metadata['resolve']['nodes']};package=next(p for p in metadata['packages'] if p['name']=='codex-linux-sandbox');queue=[package['id']];seen=set()
        while queue:
            id=queue.pop()
            if id in seen:continue
            seen.add(id)
            for dep in nodes[id]['deps']:
                if id==package['id'] or any(k['kind']!='dev' for k in dep['dep_kinds']):queue.append(dep['pkg'])
        names_resolved=sorted({packages[id]['name'] for id in seen});write(self.output/'selected-build-closure.json',{'root':'codex-linux-sandbox','rootDevDependenciesIncluded':True,'transitiveDevDependenciesExcluded':True,'packageCount':len(seen),'names':names_resolved,'v8Present':'v8' in names_resolved,'helperAutobuild':False})
        need('v8' not in names_resolved,'unexpected_v8_build_closure_requires_changed_acquisition')
        for lane in ['baseline','candidate']:
            source=self.root/lane;before=self.snapshot(source,names)
            self.ok(lane+'-fullfmt',['just','fmt'],source/'codex-rs',600,offline)
            after=self.snapshot(source,names);write(self.output/(lane+'-formatted-source.json'),{'before':before,'after':after,'unchanged':before==after})
            need(before==after,'formatter_changed_frozen_'+lane)
            self.verify_tree(source,'instrumented-baseline-v1' if lane=='baseline' else 'candidate-v1')
        self.metadata_guard()

    def retain_junit(self, target, stage):
        record={'present':False,'rawRetainedDurably':False}
        try:
            junit=target/'nextest/local/junit.xml';record['present']=junit.is_file()
            if record['present']:
                raw=junit.read_bytes();record.update(rawBytes=len(raw),rawSha256=sha(raw))
                normalize_xml(raw,{})  # Audit exact original XML before durable retention.
                normalized=normalize_xml(raw,self.replacements)
                raw_dir=self.output/stage/'raw';raw_dir.mkdir(parents=True,exist_ok=True)
                (raw_dir/'junit.xml').write_bytes(raw)
                record.update(rawRetainedDurably=True,rawArtifactPath=stage+'/raw/junit.xml')
                (self.output/stage/'junit.xml').write_bytes(normalized)
                record.update(normalizedBytes=len(normalized),normalizedSha256=sha(normalized),normalization='XML parse/serialization with owned-path replacement; identities preserved')
        except BaseException as error:record['retentionFailure']=type(error).__name__
        try:write(self.output/stage/'junit-binding.json',record)
        except BaseException as error:record['retentionFailure']=record.get('retentionFailure') or 'binding_'+type(error).__name__
        if record.get('retentionFailure'):
            if not hasattr(self,'retention_failures'):self.retention_failures=[]
            self.retention_failures.append({'stage':stage,'failure':record['retentionFailure']})
        return record

    def qualify(self):
        for lane in ['baseline','candidate']:
            source=self.root/lane;target=self.root/(lane+'-target');target.mkdir();need(not any(target.iterdir()),'qualification_target_not_fresh')
            need(self.free()>=14*GIB,'fresh_compile_below_14GiB')
            env={'CARGO_TARGET_DIR':str(target),'CARGO_NET_OFFLINE':'true','UV_OFFLINE':'true'}
            write(self.output/(lane+'-target-admission.json'),{'path':'<CAMPAIGN>/'+lane+'-target','emptyImmediatelyBeforeCompile':True,'freeBytes':self.free(),'debugSymbols':0,'debugAssertionsForcedByUnchangedWrapper':True,'incremental':0,'buildJobs':2,'reusedCompiledArtifacts':False})
            base=['just','test','-p','codex-linux-sandbox','--lib','--locked','--offline','--test-threads','2','--retries','0','--success-output','immediate','--failure-output','immediate']
            try:self.ok(lane+'-compile',base+['-E','none()','--no-tests','pass'],source/'codex-rs',3000,env)
            finally:self.retain_junit(target,lane+'-compile')
            need(not getattr(self,'retention_failures',[]),'junit_retention_hold')
            binaries=[p for p in (target/'debug/deps').glob('codex_linux_sandbox-*') if p.is_file() and not p.suffix and p.stat().st_mode&0o111]
            need(len(binaries)==1,'qualification_binary_count')
            with binaries[0].open('rb') as executable:need(executable.read(4)==b'\x7fELF','qualification_binary_identity')
            retained=self.root/'binaries'/lane;retained.mkdir();shutil.copy2(binaries[0],retained/binaries[0].name);binary=file_record(binaries[0]);need(file_record(retained/binaries[0].name)==binary,'retained_binary_hash')
            write(self.output/(lane+'-binary.json'),{'filename':binaries[0].name,**binary,'retained':True})
            phases=[(lane+'-focused',self.pins['focusedCases'])]
            if lane=='candidate':phases.append(('candidate-module',self.pins['fullModuleCases']))
            for stage,cases in phases:
                junit=target/'nextest/local/junit.xml'
                if junit.exists():junit.unlink()  # Prior compile/phase XML is already preserved below or compile-only.
                expression=' | '.join('test(='+name+')' for name in cases)
                try:row=self.run(stage,base+['-E',expression],source/'codex-rs',300,env)
                finally:self.retain_junit(target,stage)
                need(not getattr(self,'retention_failures',[]),'junit_retention_hold')
                need((self.output/stage/'junit.xml').is_file(),'missing_or_withheld_junit_'+stage);normalized=(self.output/stage/'junit.xml').read_bytes()
                log=(self.output/stage/'combined.log').read_text();classification=classify(log,normalized,cases,self.pins['expectedBaselineFailure'] if lane=='baseline' else None,self.pins['baselineFailureLocation'] if lane=='baseline' else None,row['exitCode']);write(self.output/stage/'classification.json',classification)
                need(file_record(binaries[0])==binary,'binary_changed_during_execution')
            self.verify_tree(source,'instrumented-baseline-v1' if lane=='baseline' else 'candidate-v1')

    def final_result(self, primary, success):
        result={'schema':'issue1056-linux-result-v1','qualified':False,'failureCode':primary,'cleanupFailure':None,'cleanup':None,'ownedHomeAndTmpRemoved':False,'commandCount':len(self.rows),'commands':self.rows,'initialFreeBytes':getattr(self,'initial_space',None),'finalFreeBytes':None,'sourceBase':self.pins['base'],'workerBudgetSeconds':self.budget_seconds,'baselineDescription':'Instrumented old ordering; expected first NotFound assertion failure aborts remaining loop iterations. Not three independent baseline failures.','rawEvidenceRetention':'Selected synthetic-user stdout/stderr/combined logs and JUnit are audited, preserved unchanged alongside normalized copies, and hash-bound. Other raw VM files and startup/environment dumps are excluded. Unsafe selected captures are withheld and qualification held.','scope':'Two baseline executions, two candidate focused executions, 24 candidate module executions only. No full suite, TUI, release, native credential or whole Issue1056 claim.'}
        try:
            result['cleanup']=clean_owned()
            if not result['cleanup']['ownedUidGoneExceptController']:result['cleanupFailure']='owned_cleanup_incomplete'
        except BaseException as error:result['cleanupFailure']='owned_cleanup_'+type(error).__name__
        if result['cleanup'] and result['cleanup']['ownedUidGoneExceptController']:
            try:
                for name in ['home','tmp']:shutil.rmtree(self.root/name)
                result['ownedHomeAndTmpRemoved']=not (self.root/'home').exists() and not (self.root/'tmp').exists()
            except BaseException as error:result['cleanupFailure']=result['cleanupFailure'] or 'owned_home_cleanup_'+type(error).__name__
        try:result['finalFreeBytes']=self.free()
        except BaseException as error:result['failureCode']=result['failureCode'] or 'resource_read_'+type(error).__name__
        result['retentionFailures']=getattr(self,'retention_failures',[])
        result['qualified']=bool(success and not result['retentionFailures'] and not result['failureCode'] and not result['cleanupFailure'] and result['ownedHomeAndTmpRemoved'])
        return result

    def main(self):
        primary=None;success=False
        try:self.provision();self.prepare_sources();self.qualify();success=True
        except BaseException as error:primary=str(error) if isinstance(error,Hold) else type(error).__name__
        try:result=self.final_result(primary,success)
        except BaseException as error:
            result={'qualified':False,'failureCode':primary,'cleanupFailure':'finalization_'+type(error).__name__,'commandCount':len(self.rows),'commands':self.rows}
        try:write(self.output/'result.json',result)
        except BaseException as error:
            # A filesystem that refuses all writes cannot hold a file receipt;
            # emit only this safe small fallback, never exception text or stacks.
            print(json.dumps({'qualified':False,'failureCode':result.get('failureCode'),'cleanupFailure':result.get('cleanupFailure'),'receiptFailure':type(error).__name__}))
            return 1
        return 0 if result['qualified'] else 1


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True);parser.add_argument('--control',type=Path,required=True);parser.add_argument('--budget-seconds',type=int,required=True);args=parser.parse_args()
    campaign=None
    try:campaign=Campaign(args.root,args.control,args.budget_seconds);return campaign.main()
    except BaseException as error:
        result={'failureCode':str(error) if isinstance(error,Hold) else type(error).__name__,'qualified':False,'uid':os.getuid(),'euid':os.geteuid(),'cleanupState':'unknown; host must reconcile exclusive UID'}
        try:
            output=args.root/'evidence';output.mkdir(exist_ok=True)
            if not (output/'initialization-failure.json').exists():write(output/'initialization-failure.json',result)
        except BaseException as receipt_error:print(json.dumps({'qualified':False,'failureCode':result['failureCode'],'receiptFailure':type(receipt_error).__name__}))
        return 1


if __name__=='__main__':sys.exit(main())
