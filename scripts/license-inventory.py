#!/usr/bin/env python3
"""Collect declared Cargo licenses and available notices, without approving redistribution."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile

MAX_TEXT_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024


def license_files(package: dict) -> tuple[list[tuple[str, bytes]], list[str]]:
    root = Path(package["manifest_path"]).parent.resolve(strict=True)
    candidates = []
    if package.get("license_file"):
        declared = Path(package["license_file"])
        candidates.append(declared if declared.is_absolute() else root / declared)
    candidates.extend(path for path in sorted(root.iterdir()) if
                      path.name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE", "UNLICENSE", "AUTHORS"))
                      and not path.is_dir())
    texts, issues, seen = [], [], set()
    for path in candidates:
        try:
            resolved = path.resolve(strict=True)
            relative = path.relative_to(root).as_posix()
            if path.is_symlink() or not resolved.is_relative_to(root) or not resolved.is_file():
                issues.append("unsafe_or_nonfile_license_path")
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            with resolved.open("rb") as stream:
                content = stream.read(MAX_TEXT_BYTES + 1)
            if len(content) > MAX_TEXT_BYTES:
                issues.append("oversized_license_text")
                continue
            content.decode("utf-8")
            texts.append((relative, content))
        except (OSError, ValueError, UnicodeError):
            issues.append("unreadable_or_non_utf8_license_text")
    if not texts:
        issues.append("license_text_not_found")
    return texts, sorted(set(issues))


def build_closure(metadata: dict) -> dict:
    """Select resolved normal/build edges, using Cargo's already filtered graph."""
    packages = {p["id"]: p for p in metadata.get("packages", [])}
    resolution = metadata.get("resolve")
    if not isinstance(resolution, dict) or resolution.get("root") not in packages:
        raise ValueError("selected-build evidence requires a resolved root")
    selected_root = packages[resolution["root"]]
    if selected_root.get("name") != "reede" or selected_root.get("source") is not None:
        raise ValueError("selected-build root must be the local Reede package")
    nodes = {node["id"]: node for node in resolution.get("nodes", [])}
    if len(nodes) != len(resolution.get("nodes", [])):
        raise ValueError("duplicate resolver node")
    seen, pending, selected_edges = set(), [resolution["root"]], {}
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        if pid not in packages or pid not in nodes:
            raise ValueError("selected-build graph has an unresolved package")
        seen.add(pid)
        deps = nodes[pid].get("deps")
        if not isinstance(deps, list):
            raise ValueError("selected-build evidence requires typed dependency edges")
        if set(nodes[pid].get("dependencies", [])) != {dep.get("pkg") for dep in deps}:
            raise ValueError("typed and untyped dependency metadata disagree")
        edges = []
        for dep in deps:
            kinds = dep.get("dep_kinds")
            if not isinstance(kinds, list) or not kinds:
                raise ValueError("dependency kind metadata is missing")
            if any(kind.get("kind") not in (None, "build", "dev") for kind in kinds):
                raise ValueError("unsupported dependency kind")
            included = [kind for kind in kinds if kind.get("kind") != "dev"]
            if included:
                if dep.get("pkg") not in packages:
                    raise ValueError("selected dependency package is missing")
                edges.append({**dep, "dep_kinds": included})
                pending.append(dep["pkg"])
        selected_edges[pid] = edges
    selected_nodes = [{**nodes[pid], "deps": selected_edges[pid],
                       "dependencies": [dep["pkg"] for dep in selected_edges[pid]]}
                      for pid in sorted(seen)]
    return {**metadata, "packages": [packages[pid] for pid in sorted(seen)],
            "resolve": {**resolution, "nodes": selected_nodes}}


def selection_scope(metadata: dict, dependency_scope: str, target: str | None) -> dict:
    root = metadata.get("resolve", {}).get("root") if isinstance(metadata.get("resolve"), dict) else None
    nodes = {node["id"]: node for node in (metadata.get("resolve") or {}).get("nodes", [])}
    features = nodes.get(root, {}).get("features")
    return {"dependency_scope": dependency_scope, "root_features": features,
            "target": target, "development_dependencies_included": dependency_scope != "selected-build",
            "target_filter": "Cargo metadata --filter-platform" if target else "all targets from supplied metadata",
            "exact_linked_binary_inventory": False}


def collect(metadata: dict, out: Path, epoch: int, *, dependency_scope: str = "metadata-inventory", target: str | None = None) -> dict:
    packages = metadata.get("packages", [])
    if not isinstance(packages, list) or not packages:
        raise ValueError("Cargo package metadata is missing")
    locals_ = [p for p in packages if p.get("source") is None]
    if len(locals_) != 1 or locals_[0].get("name") != "reede":
        raise ValueError("license collection requires standalone Reede metadata, not the commercial workspace")
    if len({p["id"] for p in packages}) != len(packages):
        raise ValueError("duplicate Cargo package IDs")
    if dependency_scope not in {"metadata-inventory", "selected-build"}:
        raise ValueError("unsupported license dependency scope")
    if dependency_scope == "selected-build":
        metadata = build_closure(metadata)
        packages = metadata["packages"]
    scope = selection_scope(metadata, dependency_scope, target)
    source_root = Path(__file__).resolve().parents[1]
    overrides_path = source_root / "scripts/license-overrides.json"
    overrides = json.loads(overrides_path.read_text()) if overrides_path.is_file() else []
    entries, components, total = [], [], 0
    for package in sorted(packages, key=lambda p: (p["name"], p["version"], p.get("source") or "")):
        name, version = package["name"], package["version"]
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name) or not re.fullmatch(r"[A-Za-z0-9_.+-]+", version):
            raise ValueError("unsupported package name or version")
        source = package.get("source")
        suffix = hashlib.sha256((source or "local-reede").encode()).hexdigest()[:12]
        texts, issues = license_files(package)
        supplemental = []
        for override in overrides:
            if (name, version, source) != (override["name"], override["version"], override["source"]):
                continue
            vcs_path = Path(package["manifest_path"]).parent / ".cargo_vcs_info.json"
            vcs = json.loads(vcs_path.read_text()) if vcs_path.is_file() else {}
            if vcs.get("git", {}).get("sha1") != override["git_commit"]:
                issues.append("supplemental_license_revision_mismatch")
                continue
            notice_path = source_root / override["file"]
            if notice_path.is_symlink() or not notice_path.resolve().is_relative_to(source_root):
                raise ValueError("supplemental notice escapes source tree")
            content = notice_path.read_bytes()
            if len(content) > MAX_TEXT_BYTES or hashlib.sha256(content).hexdigest() != override["sha256"]:
                raise ValueError("supplemental notice checksum/size mismatch")
            content.decode("utf-8")
            texts.append(("supplemental/" + override["file"], content))
            supplemental.append({"url": override["upstream_url"], "git_commit": override["git_commit"], "sha256": override["sha256"]})
            issues = [issue for issue in issues if issue != "license_text_not_found"]
        files = []
        for index, (original, content) in enumerate(texts):
            total += len(content)
            if total > MAX_TOTAL_BYTES:
                raise ValueError("license archive exceeds total size limit")
            archive_path = f"cargo/{name}-{version}-{suffix}/{index:02d}.txt"
            entries.append((archive_path, content))
            files.append({"package_path": original, "archive_path": archive_path,
                          "sha256": hashlib.sha256(content).hexdigest()})
        expression = package.get("license")
        if not expression:
            issues.append("license_declaration_missing")
        components.append({"name": name, "version": version,
                           "source": source, "declared_license": expression,
                           "texts": files, "supplemental_sources": supplemental,
                           "review_items": sorted(set(issues))})
    out.mkdir(parents=True, exist_ok=True)
    archive_path = out / "THIRD_PARTY_LICENSES.tar.gz"
    with archive_path.open("xb") as stream, gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=epoch) as compressed, tarfile.open(fileobj=compressed, mode="w") as archive:
        for name, content in entries:
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(content), epoch, 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(content))
    report = {
        "schema": "reede-license-evidence-v1",
        "scope": "standalone selected-feature normal/build dependency closure" if dependency_scope == "selected-build" else "standalone supplied Cargo metadata inventory; may include development and target-specific packages",
        "selection": scope,
        "collection": "declared license_file, common root LICENSE/COPYING/NOTICE/AUTHORS files and exact-revision pinned supplements; nested third-party notices require review",
        "legal_review": "not_run", "advisory_scan": "not_run", "publication_ready": False,
        "component_count": len(components), "license_text_count": len(entries),
        "components": components,
    }
    with (out / "license-evidence.json").open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--epoch", type=int, default=0)
    parser.add_argument("--dependency-scope", choices=["metadata-inventory", "selected-build"], default="metadata-inventory")
    parser.add_argument("--target", help="target previously supplied to Cargo metadata --filter-platform")
    args = parser.parse_args()
    report = collect(json.loads(args.metadata.read_text()), args.out, args.epoch, dependency_scope=args.dependency_scope, target=args.target)
    print(json.dumps({"components": report["component_count"], "texts": report["license_text_count"], "legal_review": "not_run"}))


if __name__ == "__main__":
    main()
