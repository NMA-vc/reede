# Contributing to Reede

Reede is pre-1.0. The Apache-2.0 package contains the authority, policy, receipt,
feedback and reference-store primitives, CLI/verifier and service SDKs. The
commercial host, durable stores and operational configuration are separate.
Contributions must keep dependencies pointing from the host to Reede.

Use Rust 1.89 or newer, Python 3.10 or newer for the Python client, and Node 22
or newer for the JavaScript client. Commands below run from the Reede root:

```sh
cargo test --locked --all-features
cargo fmt -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
python3 scripts/check-one-way-dependency.py
python3 -m unittest discover -s scripts/tests -v
PYTHONPATH=sdk/python REEDE_VERIFY_BIN=/absolute/path/verify \
  python3 -m unittest discover -s sdk/python/tests -v
REEDE_VERIFY_BIN=/absolute/path/verify node --test sdk/typescript/test/*.test.js
```

The live SDK/server contract gate is documented in
[sdk/README.md](sdk/README.md) and requires loopback networking.

Include the problem, expected behavior, a minimal reproduction and relevant
regression coverage in a pull request. Preserve receipt compatibility or version
wire-format changes explicitly. Do not commit credentials, private tenant data,
production receipts, generated signing keys or commercial source to this package.
Report security issues using [SECURITY.md](SECURITY.md).

Release candidates are produced by `scripts/package-release.py`. They remain
unsigned and must not be presented as audited or publication-ready. Maintainers
must finish the documented security, licensing, ownership and signing gates on
the exact source and packages being published.
