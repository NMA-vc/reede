import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'audit-rustsec.py'
spec = importlib.util.spec_from_file_location('audit_rustsec', SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def sample_inventory():
    packages = [{'id':'local-reede','name':'reede','version':'0.1.0','source':None},
                {'id':'registry-real','name':'real-crate','version':'1.2.3','source':audit.CRATES_IO}]
    return {'packages':packages,'resolve':{'root':'local-reede','nodes':[
        {'id':'local-reede','deps':[{'name':'renamed_alias','pkg':'registry-real','dep_kinds':[{'kind':None,'target':None}]}]},
        {'id':'registry-real','features':['std'],'deps':[]}]}}, {'package':[dict(p) for p in packages]}


class InventoryTests(unittest.TestCase):
    def test_exact_lock_inventory_and_renamed_dependency_path(self):
        metadata,lock=sample_inventory()
        packages=audit.inventory(metadata,lock)
        self.assertEqual([p['name'] for p in packages],['real-crate','reede'])
        paths,_=audit.dependency_paths(metadata)
        self.assertEqual(paths['registry-real'][0]['to'],'real-crate@1.2.3')
        self.assertEqual(paths['registry-real'][0]['dependency_name'],'renamed_alias')

    def test_wrong_versions_sources_and_duplicates_refused(self):
        metadata,lock=sample_inventory()
        for replacement in ['version','source']:
            wrong=copy.deepcopy(lock);wrong['package'][1][replacement]='different'
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                audit.inventory(metadata,wrong)
        metadata['packages'].append(copy.deepcopy(metadata['packages'][1]))
        with self.assertRaises(ValueError):audit.inventory(metadata,lock)

    def test_commercial_local_package_refused(self):
        metadata,lock=sample_inventory()
        metadata['packages'][0]['name']='host-core'
        with self.assertRaises(ValueError):audit.inventory(metadata,lock)


class SnapshotTests(unittest.TestCase):
    def fixture(self,directory):
        path='crates/real-crate/RUSTSEC-2026-0001.md'
        data=b'```toml\n[advisory]\nid="RUSTSEC-2026-0001"\npackage="real-crate"\ndate="2026-01-01"\n[versions]\npatched=[">=1.2.4"]\n```\n\n# Fixture\n'
        entry={'path':path,'sha':audit.blob_sha(data),'size':len(data)}
        descriptor={'schema':'reede-rustsec-snapshot-v1','repository':'https://github.com/RustSec/advisory-db',
                    'commit':'1'*40,'tree_sha':'2'*40,'commit_date':'2026-01-01T00:00:00Z',
                    'commit_signature_verification':{'verified':False,'reason':'unsigned'},
                    'tree_truncated':False,'inventory_package_names':['real-crate','reede'],
                    'advisory_index':[entry],'included_files':[entry]}
        target=directory/path;target.parent.mkdir(parents=True);target.write_bytes(data)
        (directory/'snapshot.json').write_text(json.dumps(descriptor))
        return descriptor,target

    def test_exact_blob_and_matching_index_required(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);descriptor,path=self.fixture(root)
            _,advisories=audit.load_snapshot(root,{'real-crate'})
            self.assertEqual(advisories[0]['title'],'Fixture')
            path.write_bytes(path.read_bytes()+b'tampered')
            with self.assertRaisesRegex(ValueError,'integrity'):audit.load_snapshot(root,{'real-crate'})

    def test_missing_file_truncated_index_and_uncovered_name_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);descriptor,_=self.fixture(root)
            with self.assertRaisesRegex(ValueError,'scope'):audit.load_snapshot(root,{'another-crate'})
            for replacement,message in [({'included_files':[]},'omits'),({'tree_truncated':True},'truncated')]:
                (root/'snapshot.json').write_text(json.dumps({**descriptor,**replacement}))
                with self.subTest(replacement=replacement), self.assertRaisesRegex(ValueError,message):
                    audit.load_snapshot(root,{'real-crate'})


class ClassificationTests(unittest.TestCase):
    fixture = SnapshotTests.fixture
    def test_vulnerability_notice_withdrawal_and_unmatched_ranges_stay_distinct(self):
        for annotation,patched,expected in [('',False,'affected_version_range_match'),
                ('informational="unmaintained"\n',False,'informational_range_match'),
                ('withdrawn="2026-01-02"\n',False,'withdrawn'),
                ('',True,'patched_range_match')]:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as temp:
                root=Path(temp);descriptor,path=self.fixture(root)
                text=path.read_text().replace('[versions]',annotation+'[versions]')
                path.write_text(text);data=path.read_bytes()
                descriptor['advisory_index'][0]['sha']=audit.blob_sha(data)
                descriptor['advisory_index'][0]['size']=len(data)
                (root/'snapshot.json').write_text(json.dumps(descriptor))
                metadata,_=sample_inventory();mp=root/'metadata.json';mp.write_text(json.dumps(metadata))
                lp=root/'Cargo.lock';lp.write_text('version=4\n[[package]]\nname="reede"\nversion="0.1.0"\n[[package]]\nname="real-crate"\nversion="1.2.3"\nsource="'+audit.CRATES_IO+'"\n')
                answers={('0.1.0','*'):{'matches':True},('1.2.3','*'):{'matches':True},('1.2.3','>=1.2.4'):{'matches':patched}}
                with patch.object(audit,'evaluate_queries',return_value=(answers,{'implementation':'fixture'})):
                    report=audit.audit(mp,lp,root,root/'matcher')
                self.assertEqual(report['evaluations'][0]['classification'],expected)
                self.assertFalse(report['publication_ready'])


@unittest.skipUnless(os.environ.get('REEDE_SEMVER_BIN'),'set REEDE_SEMVER_BIN for pinned Cargo-semver integration')
class OfficialSemverTests(unittest.TestCase):
    def test_exact_cargo_rules_and_explicit_refusal(self):
        answers,provenance=audit.evaluate_queries(Path(os.environ['REEDE_SEMVER_BIN']),{
            ('0.23.45','>=0.23.46'),('0.23.46','>=0.23.46'),('0.21.12','>=0.23.46'),
            ('0.0.4','^0.0.3'),('1.2.99','>1.2'),('1.3.0-beta.1','>=1.2')})
        self.assertFalse(answers['0.23.45','>=0.23.46']['matches'])
        self.assertTrue(answers['0.23.46','>=0.23.46']['matches'])
        self.assertFalse(answers['0.21.12','>=0.23.46']['matches'])
        self.assertFalse(answers['0.0.4','^0.0.3']['matches'])
        self.assertFalse(answers['1.2.99','>1.2']['matches'])
        self.assertEqual(answers['1.3.0-beta.1','>=1.2']['not_evaluated'],'unsupported_prerelease')
        self.assertEqual(provenance['implementation'],audit.SEMVER_TOOL)


if __name__=='__main__':unittest.main()
