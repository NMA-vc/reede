# Security policy

Reede 0.1.x is pre-1.0. No stable production-support window or external security
certification is declared. Only the current development line receives fixes;
consumers should review changes and pin an exact reviewed version.

Do not post exploitable vulnerability details, tenant data, tokens or private
keys in public issues. Use the repository's private vulnerability reporting
feature when enabled. If it is unavailable, contact a maintainer through an
existing published private channel before sending sensitive details. This
package does not invent a separate reporting address or promise response times.

Include affected versions, prerequisites, a minimal synthetic reproduction,
expected versus observed behavior and impact. Test only infrastructure you own
or are authorized to assess. Do not probe production or third-party services.

The library does not provision a secure host. Production isolation requires a
supported configured backend, actual sandbox enforcement and effective network
controls. In-memory stores are reference implementations. A valid signed receipt
establishes the signed assertion and chain integrity under a trusted key; it does
not establish that a compromised signer reported real execution truth. Trusted
head/count information is required to assess export completeness. RFC 3161
timestamp verification alone does not establish legal qualification.

Release checksums detect corruption relative to the accompanying manifest.
Without a separately authenticated manifest/signature they do not establish
publisher identity. Current candidates are unsigned. Do not describe internal
tests or agent-assisted source review as an independent security audit.
