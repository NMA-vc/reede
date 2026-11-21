# Offline TSA verification

The committed `reede-v1-timestamped-vector.json` is deliberately a **pending template**. Its receipt hash and Ed25519 signature are fixed, while `tsa_token` is `null`; it is not described as cryptographically timestamped.

`verify_family_vectors` creates a fresh, short-lived RSA-2048 CA and exclusive time-stamping leaf inside a private temporary directory, issues real RFC 3161 responses for both links of a signed chain, verifies each response against its request and generated CA, extracts the same bare CMS tokens, and invokes the real offline verifier with that runtime CA. A drop guard removes all generated certificates, keys, requests, responses, tokens, serials, and chains, including during panic. No network or system provider trust is used.

Production trust is separately provisioned at runtime. Operators must supply the selected provider CA bytes and verify its fingerprint through the owner runbook; this repository does not bundle or default provider certificates, fingerprints, private keys, or tokens.
