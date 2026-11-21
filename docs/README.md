# Public specifications

Publishing these documents does not assert that every proposed control-plane
operation is implemented.

- [reede serve ingest guide](ingest.md) covers the local OTLP ingest and its reported receipts.

- [Control-plane contract](REEDE_CONTROL_PLANE_CONTRACT.md) and
  [OpenAPI](reede-control-plane-v1.openapi.yaml) define the proposed API.
- [Receipt encoding specification](receipt-encoding-spec.md) is the historical
  O5 document. Read its [reede-v1 wire addendum](receipt-encoding-spec-addendum-reede-v1-wire.md)
  for content-hash recomputation and the current two-tier verifier contract.
- [reede-v2 receipt wire format](receipt-wire-v2.md) is the current emission
  format: 11 signed fields, signer key id, and the chain rules.
- [Pending timestamps and two-tier status](decisions/H8-pending-timestamp-two-tier.md)
  explains why a valid signature does not establish a trusted timestamp.

Historical references to `reede-verify` name the binary now built as `verify`;
see the [current verifier commands](../README.md#verify-a-receipt). The original
O5 document also describes host-application producer encodings and an old Python SDK.
Those producer implementations are outside this crate. There is no Python SDK
here; the catalog claim was parked by the accepted D6 decision.

Internal build plans, private handovers and deployment configuration are not
included in this specification set.
