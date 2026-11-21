import importlib.util
import json
import subprocess
import io
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "check-one-way-dependency.py"
spec = importlib.util.spec_from_file_location("boundary", SCRIPT)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)

class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.reede = self.base / "repo/reede"
        self.reede.mkdir(parents=True)
        self.outside = self.base / "outside"
        self.outside.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def graph(self, edges=()):
        rows = [
            ("root", self.reede, None),
            ("nested", self.reede / "nested", None),
            ("registry", self.base / "registry", "registry+https://crates.io"),
            ("git", self.base / "git-dep", "git+https://example.invalid/dep#rev"),
            ("unused", self.outside / "unused", None),
            ("escape", self.outside / "escape", None),
            ("far", self.base / "elsewhere", None),
        ]
        packages, ids = [], {}
        for name, folder, source in rows:
            folder.mkdir(parents=True, exist_ok=True)
            manifest = folder / "Cargo.toml"
            manifest.write_text("[package]\n", encoding="utf-8")
            ids[name] = f"{name} 1.0 ({source or 'path+' + folder.as_uri()})"
            packages.append({"id": ids[name], "manifest_path": str(manifest), "source": source})
        nodes = [{"id": ids[name], "dependencies": [ids[b] for a, b in edges if a == name]}
                 for name, _, _ in rows]
        return {"packages": packages, "resolve": {"nodes": nodes}}, ids

    def test_registry_git_nested_and_unreachable_outside_allowed(self):
        graph, _ = self.graph((("root", "nested"), ("root", "registry"),
                               ("nested", "git")))
        checker.check_graph(graph, self.reede)

    def test_empty_roots_fail(self):
        graph, _ = self.graph()
        for package in graph["packages"][:2]:
            package["manifest_path"] = str(self.outside / "unused/Cargo.toml")
        with self.assertRaisesRegex(checker.BoundaryError, "empty Reede roots"):
            checker.check_graph(graph, self.reede)

    def test_direct_transitive_and_outside_checkout_escape_fail(self):
        cases = ((("root", "escape"),), (("root", "nested"), ("nested", "escape")),
                 (("root", "far"),))
        for edges in cases:
            graph, ids = self.graph(edges)
            if ("root", "far") in edges:
                package = next(p for p in graph["packages"] if p["id"] == ids["far"])
                manifest = self.base / "other-checkout/Cargo.toml"
                manifest.parent.mkdir()
                manifest.write_text("[package]\n", encoding="utf-8")
                package["manifest_path"] = str(manifest)
            with self.assertRaisesRegex(checker.BoundaryError, "escapes Reede"):
                checker.check_graph(graph, self.reede)

    def test_symlink_escape_fails(self):
        graph, ids = self.graph((("root", "escape"),))
        package = next(p for p in graph["packages"] if p["id"] == ids["escape"])
        link = self.reede / "link"
        link.mkdir()
        package["manifest_path"] = str(link / "Cargo.toml")
        Path(package["manifest_path"]).symlink_to(self.outside / "escape/Cargo.toml")
        with self.assertRaisesRegex(checker.BoundaryError, "escapes Reede"):
            checker.check_graph(graph, self.reede)

    def test_missing_canonical_root_fails_even_with_nested_root(self):
        graph, ids = self.graph((("nested", "registry"),))
        graph["packages"] = [p for p in graph["packages"] if p["id"] != ids["root"]]
        graph["resolve"]["nodes"] = [n for n in graph["resolve"]["nodes"] if n["id"] != ids["root"]]
        with self.assertRaisesRegex(checker.BoundaryError, "canonical Reede package missing"):
            checker.check_graph(graph, self.reede)

    def test_malformed_sources_and_manifest_paths_fail(self):
        for source in ("", "path+file:///outside", "unknown+https://example.invalid"):
            graph, ids = self.graph((("root", "registry"),))
            package = next(p for p in graph["packages"] if p["id"] == ids["registry"])
            package["source"] = source
            with self.assertRaisesRegex(checker.BoundaryError, "unrecognized source"):
                checker.check_graph(graph, self.reede)
        graph, _ = self.graph()
        graph["packages"][0]["manifest_path"] = 42
        with self.assertRaisesRegex(checker.BoundaryError, "invalid manifest path"):
            checker.check_graph(graph, self.reede)
        graph, _ = self.graph()
        graph["packages"][0]["manifest_path"] = str(self.base / "missing" / "Cargo.toml")
        with self.assertRaisesRegex(checker.BoundaryError, "missing or malformed manifest"):
            checker.check_graph(graph, self.reede)

    def test_missing_resolution_nodes_and_duplicate_ids_fail(self):
        graph, _ = self.graph()
        graph["resolve"]["nodes"][0]["dependencies"] = ["absent"]
        with self.assertRaisesRegex(checker.BoundaryError, "missing dependency"):
            checker.check_graph(graph, self.reede)
        invalid, _ = self.graph()
        invalid["resolve"] = None
        with self.assertRaisesRegex(checker.BoundaryError, "no resolved dependency graph"):
            checker.check_graph(invalid, self.reede)
        graph, _ = self.graph()
        graph["packages"].append(dict(graph["packages"][0]))
        with self.assertRaisesRegex(checker.BoundaryError, "duplicate package"):
            checker.check_graph(graph, self.reede)
        graph, _ = self.graph()
        graph["resolve"]["nodes"].append(dict(graph["resolve"]["nodes"][0]))
        with self.assertRaisesRegex(checker.BoundaryError, "duplicate resolver"):
            checker.check_graph(graph, self.reede)
        graph, _ = self.graph()
        graph["resolve"]["nodes"].pop()
        with self.assertRaisesRegex(checker.BoundaryError, "missing resolver"):
            checker.check_graph(graph, self.reede)
        graph, _ = self.graph()
        graph["packages"][0]["id"] = ""
        with self.assertRaisesRegex(checker.BoundaryError, "missing or invalid id"):
            checker.check_graph(graph, self.reede)
        graph, _ = self.graph()
        graph["resolve"]["nodes"][0]["id"] = ""
        with self.assertRaisesRegex(checker.BoundaryError, "resolver node has missing"):
            checker.check_graph(graph, self.reede)

    def test_symlinked_directory_and_canonical_manifest_escape_fail(self):
        graph, ids = self.graph((("root", "escape"),))
        link = self.reede / "linked-directory"
        link.symlink_to(self.outside / "escape", target_is_directory=True)
        next(p for p in graph["packages"] if p["id"] == ids["escape"])["manifest_path"] = str(link / "Cargo.toml")
        with self.assertRaisesRegex(checker.BoundaryError, "escapes Reede"):
            checker.check_graph(graph, self.reede)

        graph, ids = self.graph()
        manifest = self.reede / "Cargo.toml"
        manifest.unlink()
        manifest.symlink_to(self.outside / "unused/Cargo.toml")
        with self.assertRaisesRegex(checker.BoundaryError, "Cargo.toml escapes Reede"):
            checker.check_graph(graph, self.reede)

    def test_nested_root_is_checked_even_if_unreachable_from_canonical_root(self):
        graph, _ = self.graph((("nested", "escape"),))
        with self.assertRaisesRegex(checker.BoundaryError, "escapes Reede"):
            checker.check_graph(graph, self.reede)

    def test_cycle_is_finite_and_still_finds_transitive_escape(self):
        graph, _ = self.graph((("root", "nested"), ("nested", "root")))
        checker.check_graph(graph, self.reede)
        graph, _ = self.graph((("root", "nested"), ("nested", "root"), ("nested", "escape")))
        with self.assertRaisesRegex(checker.BoundaryError, "escapes Reede"):
            checker.check_graph(graph, self.reede)

    def test_empty_and_malformed_graphs_fail_closed(self):
        for invalid in [None, [], {}, {"packages": [], "resolve": {}},
                        {"packages": [None], "resolve": {"nodes": [{}]} }]:
            with self.subTest(invalid=invalid), self.assertRaises(checker.BoundaryError):
                checker.check_graph(invalid, self.reede)
        for field, value in [("dependencies", None), ("dependencies", "root")]:
            graph, _ = self.graph()
            graph["resolve"]["nodes"][0][field] = value
            with self.assertRaisesRegex(checker.BoundaryError, "malformed dependencies"):
                checker.check_graph(graph, self.reede)
        graph, _ = self.graph()
        graph["packages"][0].pop("source")
        with self.assertRaisesRegex(checker.BoundaryError, "no source field"):
            checker.check_graph(graph, self.reede)
        graph, _ = self.graph()
        graph["packages"][0]["manifest_path"] = "Cargo.toml"
        with self.assertRaisesRegex(checker.BoundaryError, "invalid manifest path"):
            checker.check_graph(graph, self.reede)
        with self.assertRaisesRegex(checker.BoundaryError, "invalid Reede root"):
            checker.check_graph(graph, self.base / "missing")

    def test_missing_dependency_resolver_node_fails(self):
        graph, ids = self.graph((("root", "registry"),))
        graph["resolve"]["nodes"] = [n for n in graph["resolve"]["nodes"] if n["id"] != ids["registry"]]
        with self.assertRaisesRegex(checker.BoundaryError, "missing resolver nodes"):
            checker.check_graph(graph, self.reede)

    def run_cli(self, responses):
        with mock.patch.object(checker, "__file__", str(self.reede / "scripts/check-one-way-dependency.py")), \
             mock.patch.object(checker.subprocess, "run", side_effect=responses) as run, \
             redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
            code = checker.main()
        return code, out.getvalue(), err.getvalue(), run.call_args_list

    def metadata_response(self, graph):
        return subprocess.CompletedProcess([], 0, json.dumps(graph), "")

    def test_cli_checks_default_and_all_feature_graphs_from_both_layouts(self):
        for root in [self.base / "monorepo/reede", self.base / "standalone"]:
            self.reede = root
            graph, _ = self.graph((("root", "registry"), ("nested", "git")))
            code, out, err, calls = self.run_cli([self.metadata_response(graph)] * 2)
            self.assertEqual(code, 0, err)
            self.assertEqual(out.count("PASS"), 2)
            self.assertEqual(len(calls), 2)
            for call in calls:
                command = call.args[0]
                self.assertEqual(command[:4], ["cargo", "metadata", "--format-version=1", "--locked"])
                self.assertEqual(command[command.index("--manifest-path") + 1], str(root / "Cargo.toml"))
                self.assertEqual(call.kwargs["cwd"], root)
            self.assertNotIn("--all-features", calls[0].args[0])
            self.assertIn("--all-features", calls[1].args[0])

    def test_cli_rejects_optional_feature_only_escape(self):
        clean, _ = self.graph((("root", "registry"),))
        bad, _ = self.graph((("root", "registry"), ("registry", "escape")))
        code, out, err, calls = self.run_cli([self.metadata_response(clean), self.metadata_response(bad)])
        self.assertEqual(code, 1)
        self.assertIn("PASS (default features)", out)
        self.assertNotIn("PASS (all features)", out)
        self.assertIn("escapes Reede", err)
        self.assertEqual(len(calls), 2)

    def test_cli_metadata_failure_and_malformed_json_fail_closed(self):
        failures = [FileNotFoundError("cargo missing"),
                    subprocess.CalledProcessError(101, ["cargo"], stderr="lock update required", output=""),
                    subprocess.CompletedProcess([], 0, "{", "")]
        for failure in failures:
            with self.subTest(failure=failure):
                code, out, err, calls = self.run_cli([failure])
                self.assertEqual(code, 1)
                self.assertNotIn("PASS", out)
                self.assertIn("ERROR", err)
                self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
