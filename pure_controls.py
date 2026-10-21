"""Offline synthetic parser/archive controls; no product, network or subprocess."""
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import xml.etree.ElementTree as ET

from evidence import Hold, normalize, normalize_xml, parse_progress, parse_junit, classify
from worker import safe_extract, Campaign

A='placeholder_journal::tests::an_exited_process_does_not_hide_a_later_mount_view'
B='placeholder_journal::tests::a_mountinfo_read_error_still_fails_closed'
CASES=[A,B]


def log(fail=False,ordinal=True):
    rows=['Test isolation: disposable profile; native keyring disabled (debug lane)']
    for i,name in enumerate(CASES,1):
        status='FAIL' if fail and name==A else 'PASS'
        counter=f'({i}/2) ' if ordinal else ''
        rows.append(f' {status} [ 0.050s] {counter}codex-linux-sandbox {name}')
    if fail:rows.append("thread panicked at placeholder_journal_tests.rs:622:9: assertion failed: `(left == right)`")
    rows.append('Summary [0.100s] 2 tests run: '+('1 passed, 1 failed' if fail else '2 passed')+', 99 skipped')
    return '\n'.join(rows)+'\n'


def xml(fail=False):
    root=ET.Element('testsuites');suite=ET.SubElement(root,'testsuite',tests='2',failures='1' if fail else '0')
    for name in CASES:
        case=ET.SubElement(suite,'testcase',name=name,classname='codex-linux-sandbox')
        if fail and name==A:ET.SubElement(case,'failure').text='placeholder_journal_tests.rs:622:9: assertion failed'
    return ET.tostring(root)


class ParserControls(unittest.TestCase):
    def test_two_pass(self):self.assertEqual(classify(log(),xml(),CASES)['passed'],2)
    def test_baseline_exact_failure(self):self.assertEqual(classify(log(True),xml(True),CASES,A,'placeholder_journal_tests.rs:622:',100)['failed'],1)
    def test_no_ordinal(self):self.assertEqual(len(parse_progress(log(ordinal=False),CASES)),2)
    def test_padded_ordinal(self):self.assertEqual(len(parse_progress(log().replace('(1/2)','( 1 / 2 )'),CASES)),2)
    def test_ansi(self):self.assertEqual(len(parse_progress(log().replace('PASS','\x1b[32mPASS\x1b[0m'),CASES)),2)
    def test_wrong_ordinal_total(self):
        with self.assertRaises(Hold):parse_progress(log().replace('(1/2)','(1/3)'),CASES)
    def test_zero_ordinal(self):
        with self.assertRaises(Hold):parse_progress(log().replace('(1/2)','(0/2)'),CASES)
    def test_duplicate_actual_record(self):
        line=log().splitlines()[1]
        with self.assertRaises(Hold):parse_progress(log().replace('Summary',line+'\nSummary'),CASES)
    def test_post_summary_repetition_not_execution(self):self.assertEqual(len(parse_progress(log()+log().splitlines()[1]+'\n',CASES)),2)
    def test_missing_body(self):
        with self.assertRaises(Hold):parse_progress(log().replace(log().splitlines()[1]+'\n',''),CASES)
    def test_wrong_binary(self):
        with self.assertRaises(Hold):parse_progress(log().replace('codex-linux-sandbox','codex-core'),CASES)
    def test_selected_skip(self):
        with self.assertRaises(Hold):parse_progress(log().replace('PASS','SKIP',1),CASES)
    def test_body_skip_marker(self):
        with self.assertRaises(Hold):parse_progress(log()+'skipping because root\n',CASES)
    def test_retry_marker(self):
        with self.assertRaises(Hold):parse_progress(log()+'RETRY 2\n',CASES)
    def test_summary_count(self):
        with self.assertRaises(Hold):parse_progress(log().replace('2 tests run','3 tests run'),CASES)
    def test_summary_outcome(self):
        with self.assertRaises(Hold):parse_progress(log().replace('2 passed','1 passed'),CASES)
    def test_duplicate_summary(self):
        with self.assertRaises(Hold):parse_progress(log()+log().splitlines()[-1],CASES)
    def test_junit_missing(self):
        with self.assertRaises(Hold):parse_junit(b'<testsuites/>',CASES)
    def test_junit_duplicate(self):
        root=ET.fromstring(xml());root[0].append(root[0][0])
        with self.assertRaises(Hold):parse_junit(ET.tostring(root),CASES)
    def test_junit_skip(self):
        root=ET.fromstring(xml());ET.SubElement(root[0][0],'skipped')
        with self.assertRaises(Hold):parse_junit(ET.tostring(root),CASES)
    def test_junit_wrong_binary(self):
        with self.assertRaises(Hold):parse_junit(xml().replace(b'codex-linux-sandbox',b'codex-core'),CASES)
    def test_junit_progress_conflict(self):
        with self.assertRaises(Hold):classify(log(),xml(True),CASES)
    def test_baseline_wrong_failure(self):
        with self.assertRaises(Hold):classify(log(True),xml(True),CASES,B,'placeholder_journal_tests.rs:622:',100)
    def test_baseline_compile_failure_not_red(self):
        with self.assertRaises(Hold):classify('error[E0659]: compile error',b'<testsuites/>',CASES,A,'placeholder_journal_tests.rs:622:',101)
    def test_baseline_wrong_assertion_line(self):
        with self.assertRaises(Hold):classify(log(True),xml(True),CASES,A,'placeholder_journal_tests.rs:600:',100)
    def test_baseline_wrong_exit(self):
        with self.assertRaises(Hold):classify(log(True),xml(True),CASES,A,'placeholder_journal_tests.rs:622:',1)
    def test_candidate_nonzero_not_pass(self):
        with self.assertRaises(Hold):classify(log(),xml(),CASES,exit_code=101)
    def test_xml_entity_denied(self):
        with self.assertRaises(Hold):parse_junit(b'<!DOCTYPE a [<!ENTITY x SYSTEM "file:///private">]><a/>',CASES)
    def test_xml_safe_path_replacement(self):
        root=ET.fromstring(xml());root[0][0].set('file','/synthetic/root/source.rs');root[0][0].text='/synthetic/root/text'
        data=normalize_xml(ET.tostring(root),{'/synthetic/root':'<CAMPAIGN>'})
        self.assertIn(b'&lt;CAMPAIGN&gt;',data);self.assertEqual(ET.fromstring(data)[0][0].get('file'),'<CAMPAIGN>/source.rs')
    def test_secret_env_rejected(self):
        with self.assertRaises(Hold):normalize(b'GITHUB_TOKEN=synthetic\n',{})
    def test_owner_path_rejected(self):
        with self.assertRaises(Hold):normalize(b'/Users/operator/private',{})
    def test_owned_path_only_normalization(self):self.assertEqual(normalize(b'/tmp/owned/x',{'/tmp/owned':'<CAMPAIGN>'}),b'<CAMPAIGN>/x')
    def test_empty_log_is_not_pass(self):
        with self.assertRaises(Hold):parse_progress('',CASES)
    def test_24_exact_cases(self):
        cases=[f'placeholder_journal::tests::synthetic_{i}' for i in range(24)];text='Test isolation: disposable profile; native keyring disabled (debug lane)\n'+'\n'.join(f'PASS [0.1s] ({i+1}/24) codex-linux-sandbox {name}' for i,name in enumerate(cases))+'\nSummary [0.5s] 24 tests run: 24 passed, 99 skipped\n'
        self.assertEqual(len(parse_progress(text,cases)),24)


class ArchiveAndRetentionControls(unittest.TestCase):
    def archive(self,folder,name,link=None):
        path=folder/'test.tar'
        with tarfile.open(path,'w') as out:
            info=tarfile.TarInfo(name)
            if link is None:info.size=2;out.addfile(info,io.BytesIO(b'ok'))
            else:info.type=tarfile.SYMTYPE;info.linkname=link;out.addfile(info)
        return path
    def test_regular_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);dest=root/'out';dest.mkdir();safe_extract(self.archive(root,'tool/bin'),dest);self.assertEqual((dest/'tool/bin').read_bytes(),b'ok')
    def test_traversal_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);dest=root/'out';dest.mkdir()
            with self.assertRaises(Hold):safe_extract(self.archive(root,'../escape'),dest)
    def test_absolute_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);dest=root/'out';dest.mkdir()
            with self.assertRaises(Hold):safe_extract(self.archive(root,'/escape'),dest)
    def test_escaping_link_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);dest=root/'out';dest.mkdir()
            with self.assertRaises(Hold):safe_extract(self.archive(root,'link','../../escape'),dest)
    def test_internal_link_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);dest=root/'out';dest.mkdir();safe_extract(self.archive(root,'link','inside'),dest);self.assertTrue((dest/'link').is_symlink())
    def test_junit_retained_before_classification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);target=root/'target';(target/'nextest/local').mkdir(parents=True);(target/'nextest/local/junit.xml').write_bytes(xml(True));campaign=Campaign.__new__(Campaign);campaign.output=root/'evidence';(campaign.output/'phase').mkdir(parents=True);campaign.replacements={str(root):'<CAMPAIGN>'};campaign.retain_junit(target,'phase');self.assertTrue((campaign.output/'phase/junit.xml').is_file());self.assertIn('rawSha256',json.loads((campaign.output/'phase/junit-binding.json').read_text()))
    def test_unsafe_junit_hash_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);target=root/'target';(target/'nextest/local').mkdir(parents=True);(target/'nextest/local/junit.xml').write_bytes(b'<!DOCTYPE bad><bad/>');campaign=Campaign.__new__(Campaign);campaign.output=root/'evidence';(campaign.output/'phase').mkdir(parents=True);campaign.replacements={};campaign.retain_junit(target,'phase');record=json.loads((campaign.output/'phase/junit-binding.json').read_text());self.assertIn('retentionFailure',record);self.assertIn('rawSha256',record);self.assertFalse((campaign.output/'phase/junit.xml').exists())
    def test_metadata_cache_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'metadata-target').mkdir();(root/'metadata-target/.rustc_info.json').write_text('{}');campaign=Campaign.__new__(Campaign);campaign.root=root;campaign.output=root/'evidence';campaign.output.mkdir();campaign.metadata_guard();self.assertTrue((campaign.output/'metadata-target-inventory.json').is_file())
    def test_compiled_metadata_target_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'metadata-target').mkdir();(root/'metadata-target/compiled.rlib').write_bytes(b'not metadata');campaign=Campaign.__new__(Campaign);campaign.root=root;campaign.output=root/'evidence';campaign.output.mkdir()
            with self.assertRaises(Hold):campaign.metadata_guard()



# These injected failures exercise receipt paths without launching any process.
from unittest.mock import patch, Mock
import subprocess
import host
import worker

class CorrectedOracleControls(unittest.TestCase):
    def replacement(self,text,tag='failure'):
        root=ET.fromstring(xml(True));root[0][0].find('failure').text='different panic at other_file.rs:1'
        if tag=='failure':root[0][0].find('failure').text=text
        else:ET.SubElement(root[0][0],tag).text=text
        return ET.tostring(root)
    def test_unrelated_combined_panic_cannot_supply_case_oracle(self):
        with self.assertRaisesRegex(Hold,'baseline_case_assertion_missing'):classify(log(True),self.replacement('different panic at other_file.rs:1'),CASES,A,'placeholder_journal_tests.rs:622:',100)
    def test_direct_failed_system_out_supported(self):
        self.assertEqual(classify(log(True),self.replacement('placeholder_journal_tests.rs:622:9 assertion failed','system-out'),CASES,A,'placeholder_journal_tests.rs:622:',100)['failed'],1)
    def test_direct_failed_system_err_supported(self):
        self.assertEqual(classify(log(True),self.replacement('placeholder_journal_tests.rs:622:9 assertion failed','system-err'),CASES,A,'placeholder_journal_tests.rs:622:',100)['failed'],1)
    def test_other_case_output_cannot_supply_oracle(self):
        root=ET.fromstring(self.replacement('different panic'));ET.SubElement(root[0][1],'system-out').text='placeholder_journal_tests.rs:622:9 assertion failed'
        with self.assertRaises(Hold):classify(log(True),ET.tostring(root),CASES,A,'placeholder_journal_tests.rs:622:',100)
    def test_junit_flaky_rejected(self):
        root=ET.fromstring(xml());ET.SubElement(root[0][0],'flakyFailure')
        with self.assertRaises(Hold):parse_junit(ET.tostring(root),CASES)
    def test_environment_dump_rejected(self):
        with self.assertRaises(Hold):normalize(b'HOME=/tmp/synthetic\nPATH=/usr/bin\n',{})


class FailureReceiptControls(unittest.TestCase):
    def campaign(self,root):
        obj=Campaign.__new__(Campaign);obj.root=root;obj.output=root/'evidence';obj.output.mkdir();obj.rows=[];obj.pins={'base':'synthetic'};obj.initial_space=100;obj.budget_seconds=10;obj.free=lambda:100
        (root/'home').mkdir();(root/'tmp').mkdir();return obj
    def host_result(self):return {'qualified':False,'failureCode':'primary_compile_failure','cleanupFailure':None,'exportFailure':None,'uidCreated':True,'exports':[],'workerExitCode':1}
    def test_worker_cleanup_exception_preserves_primary_and_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);obj=self.campaign(root);obj.provision=Mock(side_effect=Hold('primary_compile_failure'))
            with patch('worker.clean_owned',side_effect=OSError('synthetic')):self.assertEqual(obj.main(),1)
            result=json.loads((obj.output/'result.json').read_text());self.assertEqual(result['failureCode'],'primary_compile_failure');self.assertEqual(result['cleanupFailure'],'owned_cleanup_OSError');self.assertFalse(result['qualified']);self.assertTrue((root/'home').exists())
    def test_worker_rmtree_failure_preserves_primary(self):
        with tempfile.TemporaryDirectory() as tmp:
            obj=self.campaign(Path(tmp))
            with patch('worker.clean_owned',return_value={'ownedUidGoneExceptController':True}),patch('worker.shutil.rmtree',side_effect=PermissionError()):result=obj.final_result('phase_deadline',False)
            self.assertEqual(result['failureCode'],'phase_deadline');self.assertEqual(result['cleanupFailure'],'owned_home_cleanup_PermissionError');self.assertFalse(result['qualified'])
    def test_worker_unknown_cleanup_does_not_remove_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            obj=self.campaign(Path(tmp))
            with patch('worker.clean_owned',return_value={'ownedUidGoneExceptController':False}),patch('worker.shutil.rmtree') as rm:result=obj.final_result(None,True)
            rm.assert_not_called();self.assertFalse(result['qualified']);self.assertFalse(result['ownedHomeAndTmpRemoved'])
    def test_worker_finalizer_exception_cannot_relabel_primary(self):
        with tempfile.TemporaryDirectory() as tmp:
            obj=self.campaign(Path(tmp));obj.provision=Mock(side_effect=Hold('phase_deadline'));obj.final_result=Mock(side_effect=OSError())
            self.assertEqual(obj.main(),1);result=json.loads((obj.output/'result.json').read_text());self.assertEqual(result['failureCode'],'phase_deadline');self.assertEqual(result['cleanupFailure'],'finalization_OSError')
    def test_host_cleanup_timeout_still_emits_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            export=Path(tmp)/'export';export.mkdir();result=self.host_result()
            with patch('host.subprocess.run',side_effect=subprocess.TimeoutExpired('pgrep',10)):host.finalize_host(result,export,None,None)
            self.assertTrue(host.emit_result(export,result));record=json.loads((export/'host-result.json').read_text());self.assertEqual(record['failureCode'],'primary_compile_failure');self.assertEqual(record['cleanupFailure'],'uid_cleanup_TimeoutExpired');self.assertFalse(record['qualified'])
    def test_host_invalid_worker_json_still_emits_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            export=Path(tmp)/'export';(export/'worker-evidence').mkdir(parents=True);(export/'worker-evidence/result.json').write_text('{');result=self.host_result();result['uidCreated']=False
            host.finalize_host(result,export,None,None);self.assertTrue(host.emit_result(export,result));self.assertEqual(result['failureCode'],'primary_compile_failure');self.assertEqual(result['exportFailure'],'worker_result_JSONDecodeError')
    def test_host_copy_failure_cannot_mask_primary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);export=root/'export';export.mkdir();result=self.host_result()
            def fake(argv,**kw):return subprocess.CompletedProcess(argv,1 if argv[0]=='pgrep' else 0,b'',b'')
            with patch('host.subprocess.run',side_effect=fake),patch('host.checked',side_effect=OSError()):host.finalize_host(result,export,root/'owned',None)
            self.assertTrue(host.emit_result(export,result));self.assertEqual(result['exportFailure'],'export_OSError');self.assertEqual(result['failureCode'],'primary_compile_failure')
    def test_unsafe_staging_file_never_copied_to_upload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);stage=root/'staging';out=root/'out';out.mkdir();(stage/'worker-evidence').mkdir(parents=True);(stage/'worker-evidence/unsafe.log').write_text('GITHUB_TOKEN=synthetic\n');result=self.host_result()
            host.audit_staging(stage,out,result,host.Budget(30));self.assertFalse((out/'worker-evidence/unsafe.log').exists());self.assertEqual(len(result['withheldExports']),1)
    def test_unselected_raw_file_never_copied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);stage=root/'staging';out=root/'out';out.mkdir();(stage/'worker-evidence/phase/raw').mkdir(parents=True);(stage/'worker-evidence/phase/raw/environment.log').write_text('synthetic');result=self.host_result()
            host.audit_staging(stage,out,result,host.Budget(30));self.assertFalse((out/'worker-evidence/phase/raw/environment.log').exists())
    def test_export_audit_exception_retains_primary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);stage=root/'staging';out=root/'out';out.mkdir();(stage/'worker-evidence').mkdir(parents=True);(stage/'worker-evidence/safe.log').write_text('synthetic');result=self.host_result()
            with patch('host.digest',side_effect=OSError()):host.audit_staging(stage,out,result,host.Budget(30))
            self.assertEqual(result['failureCode'],'primary_compile_failure');self.assertEqual(result['exportFailure'],'audit_OSError')
    def test_worker_raw_stream_exact_and_normalized_separate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);obj=self.campaign(root);obj.replacements={'/tmp/synthetic':'<CAMPAIGN>'};raw=root/'stdout';data=b'/tmp/synthetic/test.rs:1\n';raw.write_bytes(data);row={'failureCode':None,'streams':{}}
            obj.retain_streams('phase',{'stdout':raw},row);self.assertEqual((obj.output/'phase/raw/stdout.log').read_bytes(),data);self.assertEqual((obj.output/'phase/stdout.log').read_bytes(),b'<CAMPAIGN>/test.rs:1\n');self.assertTrue(row['streams']['stdout']['rawRetainedDurably'])
    def test_worker_raw_secret_withheld_with_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);obj=self.campaign(root);obj.replacements={};raw=root/'stdout';raw.write_bytes(b'GITHUB_TOKEN=synthetic\n');row={'failureCode':'phase_deadline','streams':{}}
            obj.retain_streams('phase',{'stdout':raw},row);self.assertFalse((obj.output/'phase/raw/stdout.log').exists());self.assertIn('rawSha256',row['streams']['stdout']);self.assertEqual(row['failureCode'],'phase_deadline')
    def test_junit_raw_exact_bytes_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);obj=self.campaign(root);obj.replacements={};target=root/'target';(target/'nextest/local').mkdir(parents=True);raw=xml(True);(target/'nextest/local/junit.xml').write_bytes(raw);result=obj.retain_junit(target,'phase');self.assertTrue(result['rawRetainedDurably']);self.assertEqual((obj.output/'phase/raw/junit.xml').read_bytes(),raw)
    def test_junit_retention_failure_does_not_raise_over_primary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);obj=self.campaign(root);obj.replacements={};target=root/'target';(target/'nextest/local').mkdir(parents=True);(target/'nextest/local/junit.xml').write_bytes(b'<!DOCTYPE bad><bad/>');record=obj.retain_junit(target,'phase');self.assertIn('retentionFailure',record);self.assertEqual(len(obj.retention_failures),1)
    def test_phase_cleanup_exception_preserves_row_and_primary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);obj=self.campaign(root);obj.raw=root/'raw';obj.raw.mkdir();obj.env={};obj.markers={};obj.replacements={};obj.deadline=10**20;obj.free=lambda:64*1024**3
            with patch('worker.subprocess.Popen',side_effect=Hold('phase_deadline')),patch('worker.clean_owned',side_effect=OSError()):
                with self.assertRaises(Hold):obj.run('synthetic',['never-executed'],root,10)
            row=json.loads((obj.output/'synthetic/result.json').read_text());self.assertEqual(row['failureCode'],'phase_deadline');self.assertEqual(row['cleanupFailure'],'owned_cleanup_OSError');self.assertEqual(len(obj.rows),1)
    def test_retention_failure_blocks_otherwise_successful_final_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            obj=self.campaign(Path(tmp));obj.retention_failures=[{'stage':'candidate-module','failure':'OSError'}]
            with patch('worker.clean_owned',return_value={'ownedUidGoneExceptController':True}):result=obj.final_result(None,True)
            self.assertFalse(result['qualified']);self.assertTrue(result['retentionFailures'])
    def test_budget_shared_remaining_shrinks(self):
        with patch('host.time.monotonic',side_effect=[100,200,8000]):
            budget=host.Budget();self.assertEqual(budget.remaining(8100),8100);self.assertEqual(budget.remaining(8100),500)
    def test_budget_expired_refuses_launch(self):
        with patch('host.time.monotonic',side_effect=[100,8501]):
            budget=host.Budget()
            with self.assertRaises(Hold):budget.remaining(8100)
    def test_budget_export_margin_explicit(self):self.assertEqual(9600-(8400+300),900)

if __name__=='__main__':unittest.main(verbosity=2)
