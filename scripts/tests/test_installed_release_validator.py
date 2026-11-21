import importlib.util
import gzip
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).parents[1] / "validate-installed-release.py"
spec = importlib.util.spec_from_file_location("installed_validator", SCRIPT)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


def python_success():
    return "\n".join(f"{name} (test_client.Cases.{name}) ... ok" for name in sorted(validator.PYTHON_CASES)) + "\nRan 8 tests in 1.0s\n\nOK\n"


def node_success():
    return "\n".join(f"ok {index} - {name}" for index, name in enumerate(sorted(validator.NODE_CASES), 1)) + "\n# tests 2\n# pass 2\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n"


class NamedCaseTests(unittest.TestCase):
    def test_real_case_names_required_not_zero_skipped_or_file_container_success(self):
        self.assertEqual(len(validator.python_report(python_success())), 8)
        self.assertEqual(len(validator.node_report(node_success())), 2)
        python_bad = ["Ran 0 tests in 0s\n\nOK\n", python_success().replace("OK", "OK (skipped=1)"),
                      python_success().replace(sorted(validator.PYTHON_CASES)[0], "test_unrelated")]
        node_bad = ["ok 1 - client.test.js\n# tests 1\n# pass 1\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n",
                    node_success().replace("# tests 2", "# tests 20"),
                    node_success().replace("# skipped 0", "# skipped 1"),
                    node_success().replace("# cancelled 0", "# cancelled 1"),
                    node_success().replace(sorted(validator.NODE_CASES)[0], "unrelated test"),
                    node_success() + "# tests 2\n"]
        for value in python_bad:
            with self.subTest(language="python", report=value), self.assertRaises(ValueError):
                validator.python_report(value)
        for value in node_bad:
            with self.subTest(language="node", report=value), self.assertRaises(ValueError):
                validator.node_report(value)


class CommandTests(unittest.TestCase):
    def test_closed_output_does_not_remove_process_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runner = validator.Runner(root)
            started = time.monotonic()
            with self.assertRaises(validator.subprocess.TimeoutExpired):
                runner.run([sys.executable, "-c", "import os,time;os.close(1);os.close(2);time.sleep(30)"], root, timeout=0.1)
            self.assertLess(time.monotonic() - started, 3)
            self.assertEqual(runner.commands[0]["status"], "failed")

    def test_stream_flood_is_bounded_and_failure_command_is_retained(self):
        for stream in ["stdout", "stderr"]:
            with self.subTest(stream=stream), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                runner = validator.Runner(root)
                started = time.monotonic()
                with self.assertRaisesRegex(ValueError, "output limit"):
                    runner.run([sys.executable, "-c", f"import sys;sys.{stream}.buffer.write(b'x'*2000000)"], root, limit=4096, timeout=2)
                self.assertLess(time.monotonic() - started, 3)
                self.assertEqual(runner.commands[0]["status"], "failed")
                self.assertTrue(all(path.stat().st_size <= 4096 for path in runner.logs.iterdir()))

    def test_timeout_stops_descendant_that_outlives_direct_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runner = validator.Runner(root)
            pid_path = root / "child.pid"
            code = ("import subprocess,sys; p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);"
                    f"open({str(pid_path)!r},'w').write(str(p.pid))")
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                runner.run([sys.executable, "-c", code], root, timeout=0.2)
            self.assertLess(time.monotonic() - started, 3)
            child = int(pid_path.read_text())
            # An orphan zombie may await container-init reaping; it must not remain live.
            deadline = time.monotonic() + 1
            while time.monotonic() < deadline:
                status = Path(f"/proc/{child}/stat")
                if not status.exists() or status.read_text().split(") ", 1)[1].startswith("Z"):
                    break
                time.sleep(0.01)
            else:
                self.fail("timed-out command descendant is still running")
            self.assertEqual(runner.commands[0]["status"], "failed")

    def test_missing_command_is_recorded_and_environment_overrides_are_isolated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runner = validator.Runner(root)
            with self.assertRaises(FileNotFoundError):
                runner.run([str(root / "missing")], root)
            self.assertIn("FileNotFoundError", runner.commands[0]["error"])
            with patch.dict(os.environ, {"PYTHONPATH": "untrusted", "NODE_OPTIONS": "untrusted", "REEDE_VERIFY_BIN": "wrong"}):
                out, _ = runner.run([sys.executable, "-c", "import os,json;print(json.dumps([os.getenv('PYTHONPATH'),os.getenv('NODE_OPTIONS'),os.getenv('REEDE_VERIFY_BIN')]))"], root, extra_env={"REEDE_VERIFY_BIN": "matching-verifier"})
            self.assertEqual(json.loads(out), [None, None, "matching-verifier"])

    def test_install_and_temporary_directory_overrides_cannot_target_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = root / "candidate"
            candidate.mkdir()
            runner = validator.Runner(root)
            overrides = {"PIP_TARGET": str(candidate / "installed"), "PIP_PREFIX": str(candidate),
                         "PIP_USER": "1", "TMPDIR": str(candidate), "TMP": str(candidate),
                         "TEMP": str(candidate), "NPM_CONFIG_LOGS_DIR": str(candidate)}
            code = ("import json,os,tempfile;f=tempfile.NamedTemporaryFile();"
                    "print(json.dumps({'target':os.getenv('PIP_TARGET'),'prefix':os.getenv('PIP_PREFIX'),"
                    "'user':os.getenv('PIP_USER'),'logs':os.getenv('NPM_CONFIG_LOGS_DIR'),'temporary':f.name}))")
            with patch.dict(os.environ, overrides):
                out, _ = runner.run([sys.executable, "-c", code], root)
            values = json.loads(out)
            self.assertEqual([values[k] for k in ["target", "prefix", "user", "logs"]], [None] * 4)
            self.assertTrue(Path(values["temporary"]).is_relative_to(runner.temporary))
            self.assertEqual(list(candidate.iterdir()), [])


class ExtractionTests(unittest.TestCase):
    def test_inflated_headers_are_bounded_before_tar_parsing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "oversized.tar.gz"
            with gzip.open(archive, "wb") as stream:
                stream.write(b"x" * 2048)
            with patch.object(validator, "MAX_ARCHIVE_BYTES", 1024):
                with self.assertRaisesRegex(ValueError, "expanded archive bytes"):
                    validator.extract(archive, root / "out")

    def test_oversized_extended_metadata_read_is_refused_before_allocation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "metadata.tar.gz"
            member = tarfile.TarInfo("metadata")
            member.type, member.size = tarfile.XHDTYPE, 2 ** 40
            with gzip.open(archive, "wb") as stream:
                stream.write(member.tobuf(format=tarfile.GNU_FORMAT))
                stream.write(b"\0" * 1024)
            with self.assertRaisesRegex(ValueError, "metadata read exceeds"):
                validator.extract(archive, root / "out")

    def test_traversal_links_and_duplicate_members_are_refused(self):
        for bad in ["../escape", "/absolute", "link", "duplicate"]:
            with self.subTest(member=bad), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                archive = root / "bad.tar.gz"
                with tarfile.open(archive, "w:gz") as bundle:
                    item = tarfile.TarInfo(bad)
                    if bad == "link":
                        item.type, item.linkname = tarfile.SYMTYPE, "../escape"
                        bundle.addfile(item)
                    else:
                        item.size = 1
                        bundle.addfile(item, io.BytesIO(b"x"))
                        if bad == "duplicate":
                            bundle.addfile(item, io.BytesIO(b"x"))
                with self.assertRaisesRegex(ValueError, "unsafe"):
                    validator.extract(archive, root / "out")

    def test_output_cannot_modify_candidate_directly_or_through_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = root / "candidate"
            candidate.mkdir()
            alias = root / "alias"
            alias.symlink_to(candidate, target_is_directory=True)
            for output in [candidate, candidate / "new", alias / "new"]:
                with self.subTest(output=output), self.assertRaisesRegex(ValueError, "outside immutable"):
                    validator.validate(candidate, output)
            self.assertEqual(list(candidate.iterdir()), [])

    def test_preexisting_output_is_not_overwritten_and_failure_report_is_unsigned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = root / "candidate"
            candidate.mkdir()
            output = root / "report"
            output.mkdir()
            with self.assertRaisesRegex(ValueError, "already exist"):
                validator.validate(candidate, output)
            with patch.object(validator.shutil, "which", return_value=None):
                report = validator.validate(candidate, root / "new-report")
            self.assertEqual(report["status"], "failed")
            self.assertFalse(report["publication_ready"])
            self.assertEqual(report["authenticity"], "not_established")
            self.assertTrue((root / "new-report/installed-validation.json").is_file())


def inventory_fixture(root):
    import hashlib
    source, candidate = root / "source", root / "candidate"
    source.mkdir()
    candidate.mkdir()
    checksum = "a" * 64
    (source / "Cargo.lock").write_text('version = 4\n[[package]]\nname="reede"\nversion="0.1.0"\n[[package]]\nname="dep"\nversion="1.0.0"\nsource="' + validator.CRATES_IO + '"\nchecksum="' + checksum + '"\n')
    (source / "Cargo.toml").write_text('[package]\nname="reede"\nversion="0.1.0"\n')
    components = [{"name": "reede", "version": "0.1.0", "purl": "pkg:cargo/reede@0.1.0"},
                  {"name": "dep", "version": "1.0.0", "purl": "pkg:cargo/dep@1.0.0", "hashes": [{"alg": "SHA-256", "content": checksum}]}]
    selection = {"dependency_scope": "selected-build", "root_features": [], "target": "x86_64-unknown-linux-gnu", "development_dependencies_included": False, "exact_linked_binary_inventory": False}
    sbom = {"components": components, "metadata": {"properties": [{"name": "cargo:selection", "value": json.dumps(selection)}]}}
    for name in ["sbom.cdx.json", "build-dependencies.cdx.json"]:
        (candidate / name).write_text(json.dumps(sbom))
    notices = {"cargo/reede/00.txt": b"local license", "cargo/dep/00.txt": b"dependency notice"}
    licenses = []
    for index, name in enumerate(["reede", "dep"]):
        path = f"cargo/{name}/00.txt"
        licenses.append({"name": name, "version": components[index]["version"], "source": None if name == "reede" else validator.CRATES_IO,
                         "texts": [{"archive_path": path, "sha256": hashlib.sha256(notices[path]).hexdigest()}], "review_items": []})
    license_doc = {"components": licenses, "component_count": 2, "license_text_count": 2, "selection": selection}
    (candidate / "license-evidence.json").write_text(json.dumps(license_doc))
    with tarfile.open(candidate / "THIRD_PARTY_LICENSES.tar.gz", "w:gz") as bundle:
        for path, content in notices.items():
            member = tarfile.TarInfo(path)
            member.size = len(content)
            bundle.addfile(member, io.BytesIO(content))
    return candidate, source, {"version": "0.1.0", "build_scope": {"dependency_selection": selection}}


class InventoryTests(unittest.TestCase):
    def test_missing_selected_root_and_wrong_source_rust_version_are_refused(self):
        for mutation in ["missing-root", "wrong-version"]:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                candidate, source, manifest = inventory_fixture(Path(tmp))
                if mutation == "missing-root":
                    file = candidate / "build-dependencies.cdx.json"
                    build = json.loads(file.read_text())
                    build["components"] = build["components"][1:]
                    file.write_text(json.dumps(build))
                else:
                    (source / "Cargo.toml").write_text('[package]\nname="reede"\nversion="9.9.9"\n')
                with self.assertRaisesRegex(ValueError, "root|identity/version"):
                    validator.check_inventories(candidate, source, manifest)

    def test_python_distribution_metadata_cannot_hide_wrong_or_duplicate_version(self):
        expected = {"names": ["reede_client"], "versions": ["0.1.0"]}
        self.assertEqual(validator.python_identity(expected, "0.1.0")["version"], "0.1.0")
        for identity in [{"names": ["reede-client"], "versions": ["9.9.9"]},
                         {"names": ["other"], "versions": ["0.1.0"]},
                         {"names": ["reede-client"], "versions": ["0.1.0", "9.9.9"]},
                         {"names": None, "versions": ["0.1.0"]}]:
            with self.subTest(identity=identity), self.assertRaisesRegex(ValueError, "distribution metadata"):
                validator.python_identity(identity, "0.1.0")

    def test_source_build_license_and_notice_inventories_must_agree(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate, source, manifest = inventory_fixture(Path(tmp))
            result = validator.check_inventories(candidate, source, manifest)
            self.assertEqual(result["source_lock_components"], 2)
            self.assertEqual(result["notice_files_verified"], 2)
            file = candidate / "build-dependencies.cdx.json"
            build = json.loads(file.read_text())
            build["components"][1]["hashes"][0]["content"] = "b" * 64
            file.write_text(json.dumps(build))
            with self.assertRaisesRegex(ValueError, "source lock"):
                validator.check_inventories(candidate, source, manifest)

    def test_duplicate_components_foreign_license_sources_and_false_scope_fail(self):
        for mutation in ["duplicate", "foreign-source", "scope"]:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                candidate, source, manifest = inventory_fixture(Path(tmp))
                file = candidate / ("sbom.cdx.json" if mutation == "duplicate" else "license-evidence.json")
                doc = json.loads(file.read_text())
                if mutation == "duplicate":
                    doc["components"].append(doc["components"][0])
                elif mutation == "foreign-source":
                    doc["components"][1]["source"] = "registry+other"
                else:
                    doc["selection"]["root_features"] = ["cli"]
                file.write_text(json.dumps(doc))
                with self.assertRaises(ValueError):
                    validator.check_inventories(candidate, source, manifest)

    def test_changed_or_unlisted_notice_is_refused(self):
        for mutation in ["changed", "extra"]:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                candidate, source, manifest = inventory_fixture(Path(tmp))
                with tarfile.open(candidate / "THIRD_PARTY_LICENSES.tar.gz", "w:gz") as bundle:
                    paths = ["cargo/reede/00.txt", "cargo/dep/00.txt"] + (["extra"] if mutation == "extra" else [])
                    for path in paths:
                        content = b"changed" if mutation == "changed" else {"cargo/reede/00.txt": b"local license", "cargo/dep/00.txt": b"dependency notice", "extra": b"unlisted"}[path]
                        member = tarfile.TarInfo(path)
                        member.size = len(content)
                        bundle.addfile(member, io.BytesIO(content))
                with self.assertRaisesRegex(ValueError, "notice archive"):
                    validator.check_inventories(candidate, source, manifest)


if __name__ == "__main__":
    unittest.main()
