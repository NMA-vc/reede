# Hosted validation of the full public candidate

The `Reede public release candidate validation` workflow runs on pull requests
that change `reede/` or this workflow, and can also be started manually. It uses
a GitHub-hosted Ubuntu 24.04 runner with read-only repository permission and no
persisted checkout credential. The job pins Rust to 1.89.0, Python to 3.12 and
Node to 24, then runs the repository's public candidate builder:

```sh
python3 reede/scripts/package-release.py \
  --out "$RUNNER_TEMP/reede-full-candidate" \
  --profile full --validate --build
```

The workflow checks the reviewed rustls0.23.46 lock and audit input presence before
building. This is a standalone build of the version-controlled public Reede export. The
full profile runs the all-feature standalone Cargo tests, the one-way dependency
boundary check, builds both native CLI binaries, creates Python wheel and source
distributions plus the npm package, and collects license and SBOM evidence. Its
all-feature tests include the named Python and Node SDK transport and verifier
conformance cases. The workflow preserves the package builder's manifest,
including `publication_ready: false`, and does not sign or publish the
candidate.

The job runs `verify-release.py` against a completed candidate and retains its
exact artifact list and hash report. It also saves `--version` and `--help`
output from both Linux x86_64 binaries. These binaries currently have no
`--version` or `--help` option: the workflow records those options as
unsupported when they return the documented usage output with exit code 1, and
fails on other nonzero statuses or unexpected output. The package builder's
full standalone tests, including SDK vectors and CLI tests, remain the
functional correctness gate. The candidate, tool versions, complete
build/conformance log and any partial output are uploaded as a run-specific
artifact, including when a build or later check fails.

When the source archive is available, the workflow separately runs the
existing `audit-rustsec.py` against standalone all-feature Cargo metadata and
the matching lockfile, using the committed official advisory snapshot and the
version-pinned `reede-cargo-semver-query` helper. The raw metadata, lockfile,
helper build log, scanner output and summary are retained. A scanner exit code
of 1 is preserved as evidence of findings or unevaluated entries; it does not
turn the snapshot scan into a complete vulnerability certification. Missing inputs,
metadata/helper failures, or absent/malformed scanner reports fail the job; findings
are retained for review rather than treated as security approval. This scan
does not check registry yanks or package behavior, and it does not establish
exploitability or platform/function reachability.

The candidate is a Linux x86_64 CI artifact for review. It remains unsigned,
`publication_ready: false`, and does not satisfy legal review, independent
security review, publisher identity, signing, tag, platform matrix or registry
publication gates. This workflow contains no credentials for those actions.
