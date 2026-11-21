"""Regression checks for the v2 scanner/evaluator provenance contract."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'audit-rustsec.py'
spec = importlib.util.spec_from_file_location('audit_rustsec_provenance', SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class ProvenanceTests(unittest.TestCase):
    def test_audit_v2_separates_scanner_and_evaluator_digests(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            local = {'id': 'local-reede', 'name': 'reede', 'version': '0.1.0', 'source': None}
            registry = {'id': 'registry-crate', 'name': 'example-crate', 'version': '1.2.3',
                        'source': audit.CRATES_IO}
            metadata = {
                'packages': [local, registry],
                'resolve': {'root': 'local-reede', 'nodes': [
                    {'id': 'local-reede', 'deps': []},
                    {'id': 'registry-crate', 'features': ['std'], 'deps': []},
                ]},
            }
            metadata_path = root / 'metadata.json'
            metadata_path.write_text(json.dumps(metadata))
            lock_path = root / 'Cargo.lock'
            lock_path.write_text(
                'version = 4\n\n[[package]]\nname = "reede"\nversion = "0.1.0"\n\n'
                '[[package]]\nname = "example-crate"\nversion = "1.2.3"\n'
                f'source = "{audit.CRATES_IO}"\n'
            )
            snapshot = root / 'snapshot'
            snapshot.mkdir()
            (snapshot / 'snapshot.json').write_text(json.dumps({
                'schema': 'reede-rustsec-snapshot-v1',
                'repository': 'https://github.com/RustSec/advisory-db',
                'commit': '1' * 40,
                'commit_date': '2026-01-01T00:00:00Z',
                'tree_sha': '2' * 40,
                'tree_truncated': False,
                'commit_signature_verification': {'verified': False, 'reason': 'fixture'},
                'inventory_package_names': ['reede', 'example-crate'],
                'advisory_index': [],
                'included_files': [],
            }))
            matcher = root / 'matcher'
            matcher.write_bytes(b'temporary matcher executable identity')
            matcher_sha = hashlib.sha256(matcher.read_bytes()).hexdigest()
            answers = {('0.1.0', '*'): {'matches': True}, ('1.2.3', '*'): {'matches': True}}
            provenance = {'implementation': 'reede-cargo-semver-query-v1 semver=1.0.28',
                          'binary_sha256': matcher_sha, 'query_count': 2}

            with patch.object(audit, 'evaluate_queries', return_value=(answers, provenance)):
                report = audit.audit(metadata_path, lock_path, snapshot, matcher)

        self.assertEqual(report['schema'], 'reede-rustsec-evidence-v2')
        self.assertEqual(report['scanner_source_sha256'], hashlib.sha256(SCRIPT.read_bytes()).hexdigest())
        self.assertEqual(report['matcher']['binary_sha256'], matcher_sha)
        self.assertEqual(report['matcher']['implementation'], provenance['implementation'])
        self.assertNotEqual(report['scanner_source_sha256'], report['matcher']['binary_sha256'])
        self.assertNotIn('helper_source_sha256', report)
        self.assertTrue(any('no source-to-binary linkage asserted' in item for item in report['limitations']))


if __name__ == '__main__':
    unittest.main()
