#!/usr/bin/env python3
"""Offline synthetic controls; no Cargo/Rust/generator/network launch."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import controller
import native as n
from worker import compare_snapshots, metadata_inventory

class NativeControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='issue1248-native-controls-');self.root=Path(self.temp.name)
    def tearDown(self):self.temp.cleanup()
    def xml(self,name=n.GENERATOR,classname=n.PACKAGE,child='',count='1'):
        return (f'<testsuites tests="{count}" failures="0" errors="0"><testsuite name="{n.PACKAGE}" tests="{count}" failures="0" errors="0"><testcase name="{name}" classname="{classname}">{child}</testcase></testsuite></testsuites>').encode()
    def log(self,ordinal='(  1/1)',prefix='PASS'):
        return f'    {prefix} [   0.050s] {ordinal} {n.PACKAGE} {n.GENERATOR}\nSummary [0.10s] 1 passed\n'.encode()
    def test_exact_ignored_generator_no_retry(self):
        a=n.generator_command();self.assertEqual(a[:5],['just','test','-p',n.PACKAGE,'--lib']);self.assertEqual(a[a.index('--run-ignored')+1],'only');self.assertEqual(a[a.index('--retries')+1],'0');self.assertEqual(a[a.index('-E')+1],'test(='+n.GENERATOR+')');self.assertIn('--locked',a);self.assertIn('--offline',a);self.assertNotIn('--no-run',a)
    def test_compile_zero_selection_ordinary(self):
        a=n.compile_command();self.assertEqual(a[:2],['just','test']);self.assertEqual(a[a.index('-E')+1],'none()');self.assertEqual(a[a.index('--no-tests')+1],'pass');self.assertNotIn('--run-ignored',a)
    def test_padding_or_no_ordinal_pass(self):
        for o in ('(1/1)','(  1/  1)',''):
            r=n.validate_generator(self.xml(),self.log(o));self.assertEqual(r['passed'],1);self.assertFalse(r['productQualified'])
    def test_wrong_identity_totals_failure_rejected(self):
        for x in (self.xml(name='other'),self.xml(classname='codex_app_server_protocol'),self.xml(count='0'),*[self.xml(child='<'+t+'/>') for t in ('failure','error','skipped','rerunFailure','flakyFailure')]):
            with self.assertRaises(RuntimeError):n.validate_generator(x,self.log())
    def test_duplicate_wrong_ordinal_postsummary_only_rejected(self):
        for log in (self.log().split(b'Summary')[0]*2+b'Summary',b'Summary\n'+self.log(),self.log('(1/2)'),self.log(prefix='FAIL'),self.log(prefix='LEAK')):
            with self.assertRaises(RuntimeError):n.validate_generator(self.xml(),log)
    def test_postsummary_duplicates_ignored(self):self.assertEqual(n.validate_generator(self.xml(),self.log()+self.log())['passed'],1)
    def test_body_skip_marker_rejected(self):
        for log in (b'running 0 tests\nSummary',self.log()+b'test skipped due to network\n',self.log(prefix='SKIP')):
            with self.assertRaises(RuntimeError):n.validate_generator(self.xml(),log)
    def test_entity_and_duplicate_case_rejected(self):
        for x in (b'<!DOCTYPE x>'+self.xml(),self.xml().replace(b'</testsuite>',b'<testcase name="extra"/></testsuite>')):
            with self.assertRaises(RuntimeError):n.validate_generator(x,self.log())
    def test_fresh_target_floor_and_absence(self):
        p=self.root/'target'
        with self.assertRaisesRegex(RuntimeError,'below_30GiB'):n.fresh_target(p,30*n.GIB-1)
        self.assertFalse(p.exists());self.assertTrue(n.fresh_target(p,30*n.GIB)['empty'])
        with self.assertRaisesRegex(RuntimeError,'not_fresh'):n.fresh_target(p,40*n.GIB)
    def test_fresh_target_symlink_refused(self):
        p=self.root/'target';p.symlink_to('/never-open')
        with self.assertRaisesRegex(RuntimeError,'not_fresh'):n.fresh_target(p,40*n.GIB)
    def test_metadata_compiled_output_refused(self):
        p=self.root/'metadata';p.mkdir();(p/'.rustc_info.json').write_text('{}');self.assertEqual(len(metadata_inventory(p)),1);(p/'x.rlib').write_bytes(b'x')
        with self.assertRaisesRegex(RuntimeError,'unexpected_cargo'):metadata_inventory(p)
    def lock(self,source,checksum=None):
        s='version=4\n[[package]]\nname="fixture"\nversion="1.0.0"\nsource='+json.dumps(source)+'\n'
        if checksum:s+='checksum='+json.dumps(checksum)+'\n'
        p=self.root/'Cargo.lock';p.write_text(s);return p
    def test_public_lock_sources_only(self):
        self.assertEqual(len(n.validate_lock(self.lock('registry+https://github.com/rust-lang/crates.io-index','a'*64))),1);self.assertEqual(len(n.validate_lock(self.lock('git+https://github.com/public/repo?rev=x#'+'a'*40))),1)
        for s in ('git+ssh://git@github.com/public/repo#'+'a'*40,'git+https://token@github.com/public/repo#'+'a'*40,'git+https://github.com/public/repo','registry+https://private.invalid/index'):
            with self.assertRaises(RuntimeError):n.validate_lock(self.lock(s))
        with self.assertRaises(RuntimeError):n.validate_lock(self.lock('registry+https://github.com/rust-lang/crates.io-index'))
    def test_cache_mismatch_unlocked_archive(self):
        d=self.root/'registry/cache/public';d.mkdir(parents=True);p=d/'fixture-1.0.0.crate';p.write_bytes(b'public');rows=[{'name':'fixture','version':'1.0.0','source':'registry+https://github.com/rust-lang/crates.io-index','checksum':hashlib.sha256(b'public').hexdigest()}];self.assertEqual(len(n.cargo_cache_inventory(self.root,rows)['registryArchives']),1);p.write_bytes(b'drift')
        with self.assertRaisesRegex(RuntimeError,'checksum'):n.cargo_cache_inventory(self.root,rows)
        p.unlink();(d/'foreign.crate').write_bytes(b'public')
        with self.assertRaisesRegex(RuntimeError,'unlocked'):n.cargo_cache_inventory(self.root,rows)
    def test_heavy_closure_refused(self):
        data=b'codex-app-server-protocol v1\ncodex-protocol v1 (*)\n';self.assertFalse(n.check_closure(data)['helperBuildExpected'])
        for x in (b'codex-core v1\n',b'v8 v1\n'):
            with self.assertRaisesRegex(RuntimeError,'heavy_closure'):n.check_closure(data+x)
    def schema(self):
        names=[n.STABLE,'codex-rs/app-server-protocol/schema/typescript/X.ts','codex-rs/app-server-protocol/schema/json/X.json']
        for name in names:
            p=self.root/'source'/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'public')
        out=self.root/'raw';out.mkdir();return self.root/'source',out,{'generatedOutputPolicy':{'paths':names,'allowAddedFiles':False,'existingRegularPathsOnly':True}}
    def test_schema_exact_snapshot(self):
        src,out,pins=self.schema();r=n.snapshot_schema(src,out,'schema-before',pins);self.assertEqual(set(r),set(pins['generatedOutputPolicy']['paths']));self.assertEqual((out/'schema-before'/n.STABLE).read_bytes(),b'public')
    def test_schema_added_deleted_link_refused(self):
        src,out,pins=self.schema();p=src/'codex-rs/app-server-protocol/schema/json/X.json';extra=p.with_name('extra.json');extra.write_bytes(b'x')
        with self.assertRaisesRegex(RuntimeError,'inventory_changed'):n.snapshot_schema(src,out,'a',pins)
        extra.unlink();p.unlink()
        with self.assertRaisesRegex(RuntimeError,'inventory_changed'):n.snapshot_schema(src,out,'b',pins)
        p.symlink_to('/never-open')
        with self.assertRaisesRegex(RuntimeError,'nonregular'):n.snapshot_schema(src,out,'c',pins)
    def test_schema_path_bound(self):
        for x in ('codex-rs/app-server-protocol/schema/json/../escape.json','codex-rs/private.json'):
            with self.assertRaisesRegex(RuntimeError,'inventory_path'):n.schema_paths({'generatedOutputPolicy':{'paths':[n.STABLE,x],'allowAddedFiles':False,'existingRegularPathsOnly':True}})
    def store(self):
        p=self.root/'source/codex-rs/target/nextest/local/junit.xml';p.parent.mkdir(parents=True);p.write_bytes(self.xml());out=self.root/'raw';out.mkdir();return self.root/'source',out,p
    def test_workspace_xml_preserved_before_overwrite(self):
        src,out,p=self.store();r=n.retain_junit(src,out,'compile');old=p.read_bytes();p.write_bytes(b'new');self.assertEqual((out/r['path']).read_bytes(),old);self.assertEqual(r['sha256'],hashlib.sha256(old).hexdigest())
    def test_xml_symlink_refused(self):
        src,out,p=self.store();p.unlink();p.symlink_to('/never-open')
        with self.assertRaisesRegex(RuntimeError,'junit_missing'):n.retain_junit(src,out)
    def test_runtime_unexpected_and_symlink_refused(self):
        src,out,p=self.store();extra=p.with_name('other');extra.write_bytes(b'x')
        with self.assertRaisesRegex(RuntimeError,'unexpected_runtime'):n.runtime_store_inventory(src)
        extra.unlink();extra.symlink_to('/never-open')
        with self.assertRaisesRegex(RuntimeError,'unexpected_runtime'):n.runtime_store_inventory(src)
    def test_runtime_cleanup_copies_only_xml(self):
        src,out,p=self.store();old=p.read_bytes();r=n.cleanup_runtime_store(src,out);self.assertTrue(r['removed']);self.assertEqual((out/'controller-junit.xml').read_bytes(),old);self.assertTrue(src.exists())
    def test_runtime_cleanup_unknown_preserved(self):
        src,out,p=self.store();extra=p.with_name('other');extra.write_bytes(b'keep')
        with self.assertRaises(RuntimeError):n.cleanup_runtime_store(src,out)
        self.assertEqual(extra.read_bytes(),b'keep');self.assertTrue(p.exists())
    def test_usage_nofollow_bounds(self):
        (self.root/'file').write_bytes(b'1234');(self.root/'link').symlink_to('/never-open');self.assertEqual(n.usage(self.root)['bytes'],4)
        with self.assertRaises(RuntimeError):n.usage(self.root,max_entries=1)
        with self.assertRaises(RuntimeError):n.usage(self.root,seconds=-1)
    def test_resource_caps(self):
        good={'bytes':0,'entries':0}
        with patch.object(n,'usage',return_value=good),patch.object(n,'group_rss',return_value={'bytes':0,'pids':[1]}):self.assertEqual(n.check_resource_sample(self.root,1)['ownedGroupRss']['pids'],[1])
        for values,group,reason in (([{'bytes':8*n.GIB+1},good],{'bytes':0},'cargo_cache_bound'),([good,{'bytes':20*n.GIB+1}],{'bytes':0},'native_target_bound'),([good,good],{'bytes':10*n.GIB+1},'memory_bound')):
            with patch.object(n,'usage',side_effect=values),patch.object(n,'group_rss',return_value=group):
                with self.assertRaisesRegex(RuntimeError,reason):n.check_resource_sample(self.root,1)
    def test_nonelf_or_symlink_refused(self):
        p=self.root/'binary';p.write_bytes(b'not exe');self.assertFalse(n.elf_file(p));p.unlink();p.symlink_to('/never-open');self.assertFalse(n.elf_file(p))
    def test_generation_cannot_change_source_or_inventory(self):
        before={'source':{'type':'regular','mode':'100644','sha256':'a'},'schema':{'type':'regular','mode':'100644','sha256':'b'}};after=json.loads(json.dumps(before));after['source']['sha256']='changed'
        with self.assertRaisesRegex(RuntimeError,'unexpected_tracked_source_delta'):compare_snapshots(before,after,['schema'])
        after=json.loads(json.dumps(before));after['extra']=after['schema']
        with self.assertRaisesRegex(RuntimeError,'tracked_inventory'):compare_snapshots(before,after,['schema'])

    def procstat(self,pid,pgid,sid,ticks=100):
        directory=self.root/str(pid);directory.mkdir(exist_ok=True)
        fields=['0']*22;fields[0]='S';fields[2]=str(pgid);fields[3]=str(sid);fields[19]=str(ticks);fields[21]='2'
        (directory/'stat').write_text(str(pid)+' (public fixture) '+' '.join(fields))
    def test_session_includes_separate_nextest_group_only(self):
        self.procstat(100,100,100);self.procstat(101,101,100);self.procstat(200,200,200)
        self.assertEqual([r['pid'] for r in n.session_members(100,self.root)],[100,101])
        self.assertEqual(n.group_rss(100,self.root)['pids'],[100,101])
    def test_session_permission_unknown_not_absence(self):
        self.procstat(100,100,100)
        with patch.object(Path,'read_text',side_effect=PermissionError('synthetic')):
            with self.assertRaisesRegex(RuntimeError,'membership_unknown'):n.session_members(100,self.root)
    def test_session_cleanup_revalidates_birth_and_handles_absence(self):
        row={'pid':101,'startTicks':100,'state':'S','pgid':101,'rssBytes':0}
        with patch.object(n.os,'getsid',return_value=1),patch.object(n,'session_members',side_effect=[[row],[row],[]]),patch.object(n.os,'kill') as kill:
            r=n.cleanup_session(100);self.assertTrue(r['ownedSessionGone']);kill.assert_called_once()
        with patch.object(n.os,'getsid',return_value=1),patch.object(n,'session_members',side_effect=[[row],[{**row,'startTicks':200}]]),patch.object(n.os,'kill') as kill:
            with self.assertRaisesRegex(RuntimeError,'pid_reused'):n.cleanup_session(100)
            kill.assert_not_called()
    def test_session_cleanup_refuses_controller_session(self):
        with patch.object(n.os,'getsid',return_value=100):
            with self.assertRaisesRegex(RuntimeError,'wrong_owned_session'):n.cleanup_session(100)

    def test_binary_ambiguity_refused_without_running_tool(self):
        target=self.root/'target';directory=target/'debug/deps';directory.mkdir(parents=True)
        header=b'\x7fELF\x02\x01'+b'\x00'*10+(3).to_bytes(2,'little')+(62).to_bytes(2,'little')
        for name in ('codex_app_server_protocol-one','codex_app_server_protocol-two'):
            p=directory/name;p.write_bytes(header);p.chmod(0o755)
        def forbidden(*args,**kwargs):raise AssertionError('must not run system tool')
        with self.assertRaisesRegex(RuntimeError,'binary_ambiguity'):n.capture_binary(target,self.root,forbidden)
    def test_metadata_root_link_refused(self):
        path=self.root/'metadata';path.symlink_to('/never-open')
        with self.assertRaisesRegex(RuntimeError,'metadata_root_not_directory'):metadata_inventory(path)
    def test_session_cleanup_deadline_no_signals(self):
        row={'pid':101,'startTicks':100,'state':'S','pgid':101,'rssBytes':0}
        with patch.object(n.os,'getsid',return_value=1),patch.object(n,'session_members',return_value=[row]),patch.object(n.os,'kill') as kill:
            with self.assertRaisesRegex(RuntimeError,'session_cleanup_deadline'):n.cleanup_session(100,seconds=-1)
            kill.assert_not_called()

    def test_actual_frozen_source_pin_schema_contract(self):
        pins=json.loads((Path(__file__).resolve().parent/'source-pins.json').read_text())
        self.assertNotIn('generatedOutputPaths',pins)
        names=n.schema_paths(pins)
        self.assertEqual(len(names),930)
        self.assertEqual(names,sorted(pins['generatedOutputPolicy']['paths']))
        self.assertIn(n.STABLE,names)
        self.assertEqual(len(pins['candidateFiles']),6)
        self.assertEqual(pins['base'],'31b9f3cad898914803503e5282cabd4e8ce5f860')
        self.assertEqual(hashlib.sha256((Path(__file__).resolve().parent/'source-pins.json').read_bytes()).hexdigest(),'708c124880939f9d1eb98d51e503099d4ab8188f813c4946f71f8f7d9e115e7a')
    def test_schema_policy_missing_or_widened_refused(self):
        pins=json.loads((Path(__file__).resolve().parent/'source-pins.json').read_text())
        for key,value in (('allowAddedFiles',True),('existingRegularPathsOnly',False)):
            changed=json.loads(json.dumps(pins));changed['generatedOutputPolicy'][key]=value
            with self.assertRaisesRegex(RuntimeError,'policy_not_exact'):n.schema_paths(changed)
        del pins['generatedOutputPolicy']
        with self.assertRaises(KeyError):n.schema_paths(pins)

    def test_controller_forwards_actual_930_schema_paths_without_launch(self):
        method=self.root/'method';method.mkdir();temp=self.root/'runner';temp.mkdir()
        frozen=Path(__file__).resolve().parent/'source-pins.json'
        (method/'source-pins.json').write_bytes(frozen.read_bytes())
        for name in ('admission.json','packet-manifest.json'):(method/name).write_text('{}')
        ident={'GITHUB_ACTIONS':'true','GITHUB_REPOSITORY':'citadelculture/CorbanuTerminal','GITHUB_EVENT_NAME':'push','GITHUB_REF':'refs/heads/'+controller.BRANCH,'GITHUB_SHA':'a'*40,'GITHUB_RUN_ID':'7','GITHUB_RUN_ATTEMPT':'1','GITHUB_RUN_NUMBER':'1','GITHUB_WORKFLOW_REF':'citadelculture/CorbanuTerminal/'+controller.WORKFLOW+'@refs/heads/'+controller.BRANCH,'ImageOS':'ubuntu24','ImageVersion':'fixture','RUNNER_TEMP':str(temp)}
        with patch.object(controller,'HERE',method),patch.object(controller,'admitted'),patch.object(controller.sys,'platform','linux'),patch.object(controller.os,'uname',return_value=SimpleNamespace(machine='x86_64')),patch.object(controller.os,'getuid',return_value=1000),patch.object(controller.os,'geteuid',return_value=1000),patch.dict(controller.os.environ,ident,clear=True),patch.object(controller.subprocess,'check_output',return_value=b'a'*40+b'\n'),patch.object(controller.shutil,'disk_usage',return_value=SimpleNamespace(free=0)),patch.object(controller.subprocess,'Popen',side_effect=AssertionError('no native launch')) as launch,patch('evidence.export_audited') as export:
            self.assertEqual(controller.main(),1)
            launch.assert_not_called()
            self.assertEqual(len(export.call_args.kwargs['schema_files']),930)
            self.assertEqual(export.call_args.kwargs['schema_files'],n.schema_paths(json.loads(frozen.read_text())))
            self.assertEqual(len(export.call_args.args[3]),6)

if __name__=='__main__':unittest.main(verbosity=2)
