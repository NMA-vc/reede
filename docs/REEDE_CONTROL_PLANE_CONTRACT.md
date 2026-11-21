# Reede Control-Plane Contract v1

**Status:** proposed implementation contract
**Owner:** Reede runtime
**Boundary decision:** the host application and operator tooling are clients of Reede, not owners of a second run lifecycle.

This document fixes the boundary between Reede and its clients. Reede owns the
runtime contract and its neutral schemas. the host application owns tenant-facing
catalog, billing and history UX; operator tooling owns operator workflows. Both
are Reede clients and must not create a second run lifecycle.

The machine-readable source is
[`reede-control-plane-v1.openapi.yaml`](reede-control-plane-v1.openapi.yaml).
Handlers, generated clients and CLI commands must be derived from that source.

## Runtime truth

The control plane has five immutable or append-only facts:

1. **AgentSpec** is a versioned, immutable manifest. Its digest covers runtime,
   instructions, input/output schemas, declared capabilities, policy, and secret
   *names*. Secret values never enter an AgentSpec.
2. **Session** is a durable, tenant-owned execution context. It has one active
   AgentSpec version and lazily materializes a sandbox on its first Task.
3. **Task** is one budgeted execution under one CredentialLease and policy
   envelope. A Task has a single terminal stop reason.
4. **Event** is an append-only envelope with stable id, per-session sequence,
   timestamp and typed payload. SSE and cursor replay carry identical envelopes.
5. **Receipt chain** is append-only evidence. The queryable `agent_run`
   projection is derived from Tasks, Events and Receipts; it is never an
   independent lifecycle authority.

## Authority and privacy

- Every request carries a bearer token. The server derives tenant and actor from
  authenticated context; request bodies never supply tenant identity as
  authority.
- Scopes are `reede:read`, `reede:run`, `reede:write`, `reede:admin`, and
  `reede:secrets`. A caller receives `404` rather than a cross-tenant existence
  signal for owned resources it cannot read.
- All mutation endpoints require `Idempotency-Key`. A replay with the same key,
  tenant and method returns the original result; a changed payload returns
  `409 idempotency_conflict` without repeating side effects.
- Secrets are write-only. AgentSpec versions expose only declared secret names;
  secret values are absent from API responses, events, logs, receipts and CLI
  arguments.
- Raw prompt/result content is emitted only when the task policy permits
  capture. Otherwise event payloads contain redacted summaries and hashes.

## Lifecycle

`POST /agents/{agent_id}/tasks` accepts work with `202 Accepted`; final output
never rides that response. Clients observe Tasks through `GET /tasks/{task_id}`
and the event stream. `POST /tasks/{task_id}/interrupt` requests cooperative
termination; `POST /tasks/{task_id}/kill` is immediate termination and revokes
the active lease.

The only task terminal states are `succeeded`, `failed`, `killed`, and
`budget_exhausted`. A budget stop stores a resumable checkpoint, settles the
reservation, revokes or suspends the lease, and appends a signed terminal
receipt. Resume creates a new Task with a new explicit authority grant and a
receipt link to the prior stop; it does not reopen the old Task.

Task truth records a tenant-safe authenticated actor reference, trigger and
optional trigger reference, exact AgentSpec digest, input hash, applicable
Workflow and Brief version references, CredentialLease and policy identifiers,
model/tool usage, settled cost and credits, provenance, and receipt verification
state. Raw input and result content are optional and governed by the immutable
capture policy. Every terminal Task has both an explicit stop reason and a
terminal receipt reference; a successful Task also has a result hash or result
reference.

Resume has one ingress: `POST /tasks/{task_id}/resume`. It requires an
`Idempotency-Key`, a prior checkpoint and terminal receipt, and a new authority
grant with a new approval. Its response identifies a newly created Task. The
prior Task and its receipts remain immutable.

## Immutable versions and evidence

`GET /agents/{agent_id}/versions` lists immutable versions newest first, and
`GET /agents/{agent_id}/versions/{version_or_digest}` retrieves an exact numeric
version or full digest. Version responses include compatibility and reapproval
state and declared secret names only; no read API returns secret values.

Task evidence is tenant-scoped. `GET /tasks/{task_id}/logs` returns stable,
oldest-first log records with capture/redaction state; raw prompts and results
are present only under a policy that permits raw capture. The receipts list and
item endpoints return the immutable chain and sufficient offline-verification
material: canonical payload and hash, signing public-key id and Ed25519
public verification material, previous/parent links, signature, separate signature and
TSA verification states, and optional embedded TSA evidence. A verifier must
not need network access to validate the signature or a supplied TSA token. They
do not expose secrets or mutable runtime history.

## Events and replay

Event ids are globally unique; `sequence` is strictly increasing within a
Session. The event endpoint supports both JSON cursor replay and SSE:

- `GET /sessions/{session_id}/events?after=<event-id>&limit=<n>` returns events
  oldest first plus an opaque next cursor.
- The same endpoint with `Accept: text/event-stream` remains open and emits
  SSE events named after `payload.type`; each `data` value is the identical
  typed `EventEnvelope` used by JSON replay.
- A reconnect begins after the last stored event id. Clients deduplicate by
  `event.id`, never timestamp.

SSE also accepts `Last-Event-ID`. If it and `after` are both supplied, they must
be identical or the server returns `cursor_conflict`; malformed, unknown, or
expired cursors return `invalid_cursor`. Idle streams emit `: heartbeat` comment
frames at least every 20 seconds. Comments have no event id or data and are not
stored. Once all selected Tasks have emitted terminal Events, the stream closes.
Event ids remain stable across JSON replay and SSE.

Every terminal Task produces a terminal event carrying an explicit stop reason,
result reference (if any), provenance links, receipt reference, and resume link
when applicable.

## Spec mutation and drift

AgentSpec updates require `expected_version`. Identical canonical content is a
no-op; any changed content creates a new immutable version. A structured diff
classifies changes as prompt/instruction, runtime, authority, capability,
egress, budget, secret-name, or schema change.

Only compatible prompt/instruction changes may hot-reload into a live Session.
Runtime, identity, resource, capability, policy and authority changes require
an explicit new Session or restart. Tool schema fingerprints are part of the
spec digest. A capability addition, removal, endpoint change, or fingerprint
change enters `approval_required` and cannot be called until a tenant-authorized
approver accepts that exact diff.

## Error envelope

All non-successful responses use the OpenAPI `Error` envelope. `code` is stable
and machine-actionable; `request_id` is always present. Structured errors cover
rate limiting, invalid/conflicting cursors, already-terminal conflicts,
evaluator and receipt-verification failure, retry delay, and bounded field
violations. Error detail must not contain secret values, raw private content,
cross-tenant identifiers, or resource-existence signals.

All collection endpoints use bounded limits and opaque next cursors. Agent and
AgentSpec version lists, Sessions, and Tasks define deterministic ordering;
Events, logs, and receipts are oldest first so a cursor can continue an
append-only history without reordering.

Because HTTP bearer authentication cannot express operation-level OAuth scopes,
each OpenAPI operation states its required scope in both its description and
`x-required-scopes`. Owned-resource lookups return `404` across tenant
boundaries. Tenant identity is never accepted as request authority.

## Release acceptance

These documents define this contract; they do **not** claim that the
runtime is shipped or implementation-complete. The contract is complete only when
handlers, a generated client, and CLI implement this same lifecycle and tenant
isolation, idempotency, replay, budget exhaustion/resume, schema reapproval,
egress, sandbox isolation, logs, and offline receipt verification pass
end-to-end against a provisioned isolation host. No handler or generated-client
implementation is part of this contract-only change.
