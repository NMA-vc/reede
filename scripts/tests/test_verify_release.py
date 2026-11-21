import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("verify_release", Path(__file__).resolve().parents[1] / "verify-release.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class CandidateIntegrityTests(unittest.TestCase):
    def candidate(self, root):
        artifact = root / "sdk.whl"
        artifact.write_bytes(b"synthetic package")
        manifest = {"schema": "reede-release-candidate-v1", "source_commit": "a" * 40,
                    "source_dirty": False, "artifacts": [{"path": "sdk.whl", "sha256": verifier.digest(artifact)}]}
        self.write_manifest(root, manifest)
        return manifest

    def write_manifest(self, root, manifest):
        (root / "release.json").write_text(json.dumps(manifest))
        lines = [f"{item['sha256']}  {item['path']}" for item in manifest["artifacts"]]
        lines.append(f"{verifier.digest(root / 'release.json')}  release.json")
        (root / "SHA256SUMS").write_text("\n".join(lines) + "\n")

    def test_valid_candidate_does_not_claim_authenticity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.candidate(root)
            report = verifier.verify(root)
            self.assertEqual(report["integrity"], "verified")
            self.assertEqual(report["authenticity"], "not_established")
            self.assertFalse(report["publication_ready"])

    def test_tampered_or_unlisted_artifact_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.candidate(root)
            (root / "sdk.whl").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "mismatch"):
                verifier.verify(root)
            self.candidate(root)
            (root / "unexpected.key").write_bytes(b"not exported")
            with self.assertRaisesRegex(ValueError, "unlisted"):
                verifier.verify(root)

    def test_path_traversal_symlinks_and_duplicate_entries_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = self.candidate(root)
            manifest["artifacts"][0]["path"] = "../sdk.whl"
            self.write_manifest(root, manifest)
            with self.assertRaises(ValueError):
                verifier.verify(root)
            manifest = self.candidate(root)
            manifest["artifacts"].append(manifest["artifacts"][0])
            self.write_manifest(root, manifest)
            with self.assertRaisesRegex(ValueError, "duplicate"):
                verifier.verify(root)
            self.candidate(root)
            (root / "sdk.whl").unlink()
            (root / "sdk.whl").symlink_to(root / "release.json")
            with self.assertRaisesRegex(ValueError, "symlink"):
                verifier.verify(root)

    def test_manifest_and_checksum_list_must_agree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = self.candidate(root)
            manifest["source_commit"] = "b" * 40
            (root / "release.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "disagree"):
                verifier.verify(root)
