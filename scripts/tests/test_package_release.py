import importlib.util
import contextlib
import io
import json
import shutil
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("package_release", Path(__file__).resolve().parents[1] / "package-release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class PublicReleaseTests(unittest.TestCase):
    def source(self, root):
        for name in release.ROOT_FILES:
            (root / name).write_text("fixture")
        (root / "src").mkdir()
        (root / "src/lib.rs").write_text("// public")

    def test_profiles_preserve_full_checks_and_explicitly_select_only_verifier(self):
        full = release.release_plan("full", "fixture-target")
        self.assertEqual(full["test_flags"], ["--all-features"])
        self.assertEqual(full["metadata_flags"], ["--all-features"])
        self.assertEqual(full["build_flags"], ["--features", "cli,ingest", "--bins"])
        self.assertEqual(full["binaries"], ["verify", "reede"])
        narrow = release.release_plan("offline-verification", "fixture-target")
        self.assertEqual(narrow["build_flags"], ["--no-default-features", "--bin", "verify"])
        self.assertEqual(narrow["binaries"], ["verify"])
        self.assertEqual(narrow["metadata_flags"], ["--no-default-features", "--filter-platform", "fixture-target"])
        self.assertEqual(narrow["license_scope"], "selected-build")
        with self.assertRaises(ValueError):
            release.release_plan("unknown")

    def test_source_and_build_sboms_keep_distinct_scopes_and_raw_licenses(self):
        packages = [{"name": "reede", "version": "0.1.0"},
                    {"name": "optional-http", "version": "1.0.0", "source": "registry+fixture"}]
        licenses = {("reede", "0.1.0", None): "Apache-2.0"}
        source = release.sbom_inventory(packages, "0.1.0", "source lockfile", licenses)
        built = release.sbom_inventory(packages[:1], "0.1.0", "selected build closure", licenses,
                                       selection={"root_features": [], "exact_linked_binary_inventory": False})
        self.assertEqual(len(source["components"]), 2)
        self.assertEqual(len(built["components"]), 1)
        self.assertNotIn("licenses", built["components"][0])
        self.assertEqual(built["components"][0]["properties"][0]["value"], "Apache-2.0")
        self.assertIn('"exact_linked_binary_inventory": false', built["metadata"]["properties"][1]["value"])

    def test_build_metadata_matches_exact_locked_versions_and_hashes(self):
        package = {"name": "dependency", "version": "1.0.0", "source": "registry+fixture"}
        lock = {"package": [{**package, "checksum": "a" * 64}]}
        self.assertEqual(release.locked_build_packages([package], lock)[0]["checksum"], "a" * 64)
        with self.assertRaisesRegex(ValueError, "lockfile"):
            release.locked_build_packages([{**package, "version": "1.0.1"}], lock)

    def test_main_license_profiles_preserve_serializable_selection_and_inventory(self):
        for profile in ["full", "offline-verification"]:
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as tmp:
                source = Path(tmp) / "source"
                source.mkdir()
                self.source(source)
                (source / "Cargo.toml").write_text('[package]\nname="reede"\nversion="0.1.0"\n')
                (source / "Cargo.lock").write_text('version=4\n[[package]]\nname="reede"\nversion="0.1.0"\n')
                (source / "scripts").mkdir()
                shutil.copyfile(Path(release.__file__).with_name("license-inventory.py"), source / "scripts/license-inventory.py")
                files = release.public_files(source)
                out = Path(tmp) / "candidate"
                def check_output(command, *, cwd=None, **kwargs):
                    if command == ["rustc", "-vV"]:
                        return "host: fixture-target\n"
                    if command[:2] == ["git", "rev-parse"]:
                        return "1" * 40 + "\n"
                    if command[:2] == ["git", "status"]:
                        return ""
                    if command[:2] == ["git", "show"]:
                        return "1234\n"
                    if command[:2] == ["git", "ls-files"]:
                        return "\0".join(str(path) for path in files) + "\0"
                    if command[:2] == ["cargo", "metadata"]:
                        root = {"id": "reede", "name": "reede", "version": "0.1.0", "source": None,
                                "manifest_path": str(cwd / "Cargo.toml"), "license": "Apache-2.0", "license_file": None}
                        node = {"id": "reede", "dependencies": [], "deps": [],
                                "features": ["cli"] if profile == "full" else []}
                        return json.dumps({"packages": [root], "resolve": {"root": "reede", "nodes": [node]}}).encode()
                    self.fail(f"unexpected command: {command}")
                argv = ["package-release.py", "--source", str(source), "--out", str(out),
                        "--profile", profile, "--licenses"]
                with patch.object(sys, "argv", argv), patch.object(release.subprocess, "check_output", side_effect=check_output), contextlib.redirect_stdout(io.StringIO()):
                    release.main()
                manifest = json.loads((out / "release.json").read_text())
                self.assertEqual(manifest["profile"], profile)
                self.assertFalse(manifest["publication_ready"])
                self.assertEqual(manifest["build_scope"]["native_binaries"], [])
                selected = json.loads((out / "license-evidence.json").read_text())["selection"]
                self.assertEqual(selected["target"], "fixture-target" if profile == "offline-verification" else None)
                self.assertEqual(selected["root_features"], [] if profile == "offline-verification" else ["cli"])
                listed = {item["path"] for item in manifest["artifacts"]}
                self.assertIn("build-dependencies.cdx.json", listed)
                self.assertIn("THIRD_PARTY_LICENSES.tar.gz", listed)

    def test_private_and_generated_files_are_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.source(root)
            (root / "CLAUDE.md").write_text("internal guidance")
            (root / "host-runtime").mkdir()
            (root / "host-runtime/private.rs").write_text("commercial")
            (root / "src/.env").write_text("SECRET=not-exported")
            files = release.public_files(root)
            self.assertIn(Path("src/lib.rs"), files)
            self.assertNotIn(Path("CLAUDE.md"), files)
            self.assertFalse(any("private" in str(p) or ".env" in str(p) for p in files))

    def test_symlink_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.source(root)
            (root / "src/private.rs").symlink_to(root / "CLAUDE.md")
            with self.assertRaises(ValueError):
                release.public_files(root)

    def test_source_archives_are_reproducible(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.source(root)
            files = release.public_files(root)
            one, two = root / "one.tar.gz", root / "two.tar.gz"
            release.source_archive(root, one, "reede-test", files, 1234)
            release.source_archive(root, two, "reede-test", files, 1234)
            self.assertEqual(one.read_bytes(), two.read_bytes())
