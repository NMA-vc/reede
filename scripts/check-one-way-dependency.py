#!/usr/bin/env python3
"""Reject resolved local dependencies outside the Reede subtree."""
import json
import subprocess
import sys
from pathlib import Path

class BoundaryError(Exception):
    pass

def inside(path, parent):
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False

def check_graph(data, reede_root):
    try:
        reede = Path(reede_root).resolve(strict=True)
    except (OSError, ValueError, RuntimeError) as exc:
        raise BoundaryError(f"invalid Reede root: {exc}") from exc
    if not reede.is_dir():
        raise BoundaryError(f"Reede root is not a directory: {reede}")
    if not isinstance(data, dict):
        raise BoundaryError("metadata root must be an object")
    packages, resolution = data.get("packages"), data.get("resolve")
    if not isinstance(packages, list) or not packages:
        raise BoundaryError("metadata packages must be a non-empty array")
    if not isinstance(resolution, dict):
        raise BoundaryError("metadata has no resolved dependency graph")
    nodes = resolution.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        raise BoundaryError("resolve.nodes must be a non-empty array")
    by_id, manifests = {}, {}
    for package in packages:
        if not isinstance(package, dict):
            raise BoundaryError("package entry is malformed")
        pid, raw, source = package.get("id"), package.get("manifest_path"), package.get("source")
        if not isinstance(pid, str) or not pid.strip():
            raise BoundaryError("package has missing or invalid id")
        if pid in by_id:
            raise BoundaryError(f"duplicate package id: {pid}")
        if not isinstance(raw, str) or not raw.strip() or not Path(raw).is_absolute():
            raise BoundaryError(f"package has invalid manifest path: {pid}")
        if "source" not in package:
            raise BoundaryError(f"package has no source field: {pid}")
        if source is not None and (
            not isinstance(source, str)
            or not source.strip()
            or not ((source.startswith("registry+") and len(source) > len("registry+"))
                    or (source.startswith("git+") and len(source) > len("git+")))
        ):
            raise BoundaryError(f"package has unrecognized source: {pid}: {source!r}")
        try:
            manifest = Path(raw).resolve(strict=True)
        except (OSError, ValueError, RuntimeError) as exc:
            raise BoundaryError(f"missing or malformed manifest for {pid}: {exc}") from exc
        if not manifest.is_file():
            raise BoundaryError(f"manifest is not a file: {manifest}")
        by_id[pid], manifests[pid] = package, manifest

    edges = {}
    for node in nodes:
        if not isinstance(node, dict):
            raise BoundaryError("resolver node is malformed")
        nid = node.get("id")
        if not isinstance(nid, str) or not nid.strip():
            raise BoundaryError("resolver node has missing or invalid id")
        if nid in edges:
            raise BoundaryError(f"duplicate resolver id: {nid}")
        if nid not in by_id:
            raise BoundaryError(f"resolver node has no package: {nid}")
        deps = node.get("dependencies")
        if not isinstance(deps, list):
            raise BoundaryError(f"resolver node has malformed dependencies: {nid}")
        for dep in deps:
            if not isinstance(dep, str) or dep not in by_id:
                raise BoundaryError(f"missing dependency node: {dep!r}")
        edges[nid] = deps
    missing = sorted(set(by_id) - set(edges))
    if missing:
        raise BoundaryError("packages missing resolver nodes: " + ", ".join(missing))

    roots = [pid for pid, path in manifests.items() if inside(path, reede)]
    if not roots:
        raise BoundaryError(f"empty Reede roots under {reede}")
    try:
        canonical_root_manifest = (reede / "Cargo.toml").resolve(strict=True)
    except (OSError, ValueError, RuntimeError) as exc:
        raise BoundaryError(f"canonical Reede Cargo.toml missing or malformed: {exc}") from exc
    canonical_ids = [pid for pid, path in manifests.items() if path == canonical_root_manifest]
    if not inside(canonical_root_manifest, reede):
        raise BoundaryError("canonical Reede Cargo.toml escapes Reede")
    if not canonical_root_manifest.is_file() or len(canonical_ids) != 1:
        raise BoundaryError(f"canonical Reede package missing from metadata: {reede / 'Cargo.toml'}")
    if any(by_id[pid]["source"] is not None for pid in canonical_ids):
        raise BoundaryError(f"canonical Reede manifest is not a local package: {reede / 'Cargo.toml'}")

    seen, pending, violations = set(), list(roots), []
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        if by_id[pid]["source"] is None and not inside(manifests[pid], reede):
            violations.append((pid, manifests[pid]))
        pending.extend(edges[pid])
    if violations:
        lines = "\n".join(f"  {path} ({pid})" for pid, path in sorted(violations))
        raise BoundaryError("local dependency escapes Reede:\n" + lines)

def main():
    reede = Path(__file__).resolve().parent.parent
    try:
        for features in ([], ["--all-features"]):
            label = "all features" if features else "default features"
            cmd = ["cargo", "metadata", "--format-version=1", "--locked",
                   "--manifest-path", str(reede / "Cargo.toml"), *features]
            try:
                result = subprocess.run(cmd, check=True, capture_output=True, text=True,
                                        cwd=reede)
            except OSError as exc:
                raise BoundaryError(f"cannot run Cargo metadata ({label}): {exc}") from exc
            except subprocess.CalledProcessError as exc:
                detail = exc.stderr.strip() or exc.stdout.strip() or str(exc.returncode)
                raise BoundaryError(f"Cargo metadata failed ({label}): {detail}") from exc
            try:
                data = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                raise BoundaryError(f"malformed Cargo metadata ({label}): {exc}") from exc
            check_graph(data, reede)
            print(f"Reede dependency boundary: PASS ({label})")
    except BoundaryError as exc:
        print("Reede dependency boundary: ERROR: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
