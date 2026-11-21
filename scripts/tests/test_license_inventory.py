import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("license_inventory", Path(__file__).resolve().parents[1] / "license-inventory.py")
licenses = importlib.util.module_from_spec(spec)
spec.loader.exec_module(licenses)


class LicenseEvidenceTests(unittest.TestCase):
    def package(self, root, name, source):
        root.mkdir()
        (root / "Cargo.toml").write_text("fixture")
        (root / "LICENSE").write_text("synthetic license text")
        return {"name": name, "version": "1.0.0", "id": name,
                "source": source, "license": "MIT", "license_file": None,
                "manifest_path": str(root / "Cargo.toml")}

    def graph(self, root):
        packages = [self.package(root / name, name, None if name == "reede" else "registry+fixture")
                    for name in ["reede", "runtime", "build", "dev", "optional-http"]]
        deps = [{"name": name, "pkg": name, "dep_kinds": [{"kind": kind, "target": None}]}
                for name, kind in [("runtime", None), ("build", "build"), ("dev", "dev")]]
        nodes = [{"id": "reede", "features": [], "deps": deps,
                  "dependencies": [dep["pkg"] for dep in deps]}]
        nodes.extend({"id": p["id"], "features": ["std"], "deps": [], "dependencies": []}
                     for p in packages if p["id"] != "reede")
        return {"packages": packages, "resolve": {"root": "reede", "nodes": nodes}}

    def test_selected_build_scope_excludes_dev_and_unused_optional_packages(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata = self.graph(root)
            report = licenses.collect(metadata, root / "out", 0,
                                      dependency_scope="selected-build", target="fixture-target")
            self.assertEqual({p["name"] for p in report["components"]}, {"reede", "runtime", "build"})
            self.assertEqual(report["selection"]["root_features"], [])
            self.assertFalse(report["selection"]["development_dependencies_included"])
            self.assertFalse(report["selection"]["exact_linked_binary_inventory"])
            self.assertNotIn("all-feature", report["scope"])
            self.assertFalse(report["publication_ready"])
            complete = licenses.collect(metadata, root / "complete", 0)
            self.assertEqual(complete["component_count"], 5)
            self.assertTrue(complete["selection"]["development_dependencies_included"])

    def test_selected_graph_rejects_wrong_root_missing_kinds_and_disagreeing_edges(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata = self.graph(root)
            metadata["resolve"]["root"] = "runtime"
            with self.assertRaisesRegex(ValueError, "local Reede"):
                licenses.build_closure(metadata)
            metadata["resolve"]["root"] = "reede"
            node = metadata["resolve"]["nodes"][0]
            node["deps"][0]["dep_kinds"] = []
            with self.assertRaisesRegex(ValueError, "kind"):
                licenses.build_closure(metadata)
            node["deps"][0]["dep_kinds"] = [{"kind": None, "target": None}]
            node["dependencies"].clear()
            with self.assertRaisesRegex(ValueError, "disagree"):
                licenses.build_closure(metadata)

    def test_reproducible_archive_preserves_notices_without_legal_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata = {"packages": [self.package(root / "root", "reede", None),
                                      self.package(root / "dep", "dependency", "registry+fixture")]}
            one, two = root / "one", root / "two"
            report = licenses.collect(metadata, one, 1234)
            licenses.collect(metadata, two, 1234)
            self.assertEqual((one / "THIRD_PARTY_LICENSES.tar.gz").read_bytes(), (two / "THIRD_PARTY_LICENSES.tar.gz").read_bytes())
            self.assertEqual(report["component_count"], 2)
            self.assertFalse(report["publication_ready"])
            self.assertEqual(report["legal_review"], "not_run")
            with tarfile.open(one / "THIRD_PARTY_LICENSES.tar.gz") as archive:
                self.assertEqual(len(archive.getmembers()), 2)
                self.assertTrue(all(member.isfile() and ".." not in member.name for member in archive))

    def test_commercial_metadata_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = self.package(root / "private", "host-private", None)
            with self.assertRaises(ValueError):
                licenses.collect({"packages": [package]}, root / "out", 0)

    def test_supplement_requires_exact_revision_and_checksum(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "project"
            (source / "scripts").mkdir(parents=True)
            (source / "docs").mkdir()
            notice = b"pinned upstream notice"
            (source / "docs/LICENSE").write_bytes(notice)
            override = {"name": "dependency", "version": "1.0.0", "source": "registry+fixture",
                        "git_commit": "exact-revision", "file": "docs/LICENSE",
                        "sha256": licenses.hashlib.sha256(notice).hexdigest(), "upstream_url": "https://example.test/pinned/LICENSE"}
            (source / "scripts/license-overrides.json").write_text(json.dumps([override]))
            dep = self.package(root / "dep", "dependency", "registry+fixture")
            (root / "dep/LICENSE").unlink()
            vcs = root / "dep/.cargo_vcs_info.json"
            vcs.write_text(json.dumps({"git": {"sha1": "wrong-revision"}}))
            metadata = {"packages": [self.package(root / "reede", "reede", None), dep]}
            with patch.object(licenses, "__file__", str(source / "scripts/license-inventory.py")):
                report = licenses.collect(metadata, root / "wrong", 0)
                item = next(p for p in report["components"] if p["name"] == "dependency")
                self.assertIn("supplemental_license_revision_mismatch", item["review_items"])
                self.assertFalse(item["texts"])
                vcs.write_text(json.dumps({"git": {"sha1": "exact-revision"}}))
                report = licenses.collect(metadata, root / "right", 0)
                item = next(p for p in report["components"] if p["name"] == "dependency")
                self.assertEqual(item["review_items"], [])
                self.assertEqual(item["supplemental_sources"][0]["sha256"], override["sha256"])
                (source / "docs/LICENSE").write_bytes(b"modified notice")
                with self.assertRaisesRegex(ValueError, "checksum"):
                    licenses.collect(metadata, root / "tampered", 0)

    def test_license_paths_cannot_escape_and_missing_texts_need_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = self.package(root / "pkg", "reede", None)
            (root / "pkg/LICENSE").unlink()
            (root / "outside").write_text("private fixture")
            (root / "pkg/LICENSE").symlink_to(root / "outside")
            package["license_file"] = str(root / "outside")
            report = licenses.collect({"packages": [package]}, root / "out", 0)
            self.assertEqual(report["license_text_count"], 0)
            self.assertIn("license_text_not_found", report["components"][0]["review_items"])
            self.assertNotIn("private fixture", json.dumps(report))
