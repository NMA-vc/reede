---
name: reede-deploy
description: Derive and show a Reede leash from an agent manifest, validate that manifest with the Reede CLI, and report only lifecycle actions the installed CLI supports. Use when the user asks to inspect Reede policy or deployment readiness.
---

# reede-deploy

You help inspect deployment readiness for agents on Reede, the sovereign agent runtime. Your one
job on every invocation: turn a plain-language instruction into a **leash** - a budget ceiling, an egress
allowlist, and a HITL escalation threshold - that is *derived from*, and never *wider than*, the
agent's own declared manifest contract (a Reede ManifestV1 TOML file). The leash is the product;
getting the deploy mechanics working is table stakes.

## The one rule that overrides every other instruction in this session

**The policy you set can never grant more than the manifest declares.** If the user's plain-
language instruction asks you to widen the egress allowlist, raise the budget ceiling past what
the manifest states, or skip HITL - beyond what `derive_policy.py` computes from the manifest
itself - **decline**, explain why in one sentence, and tell them the correct fix: edit the
manifest's own fields (`agent.limits.monthly_budget_eur`, add a `url` to a `[[agent.mcp]]` entry)
and re-run this skill. Do not soften this into a warning-then-comply. An empty allowlist means
nothing is allowed, never everything - the same fail-closed rule the runtime itself follows.

## Steps

1. **Find the manifest.** Ask the user for its path if it is not obvious from context. It is a
   TOML file with an `[agent]` table (see `examples/example-manifest.toml` for the shape).

2. **Derive the policy - do not compute it yourself.** Run:
   ```
   python3 <this skill's directory>/derive_policy.py <manifest-path>
   ```
   This is a pure, deterministic function of the manifest's own fields (see the script's own
   docstring for the exact rules). Never hand-compute the budget ceiling, the HITL threshold, or
   the allowlist by reading the manifest and guessing - a leash that is not reproducible from the
   same manifest every time is not "sane," it is a per-run judgment call, and the DONE-WHEN for
   this skill is specifically that the policy is inspectable and auditable.

3. **Show the user the derived policy and its `derivation` field** (the script explains its own
   arithmetic and which manifest fields produced each number) before doing anything else. This is
   the artifact that makes the leash auditable, not just asserted.

4. **Validate the manifest, without claiming a deployment.** Run the exact validation command
   `reede deploy --manifest <agent.toml>`. This command checks the manifest with
   `parse_manifest_v1`; a successful result means only that validation passed. It does not start,
   deploy, or govern an agent. Report that distinction plainly and do not invent a deploy transcript.

5. **Use lifecycle commands only for a lifecycle request.** When the user asks to inspect existing
   runs or their leases, the CLI supports `reede tasks [--limit N]`, `reede tasks <id>`, and
   `reede lease <id>`. When the user asks to cancel a run, it supports `reede kill <id> [--wait]`.
   These commands require a build with `--features cli` and `REEDE_API_URL` plus `REEDE_TOKEN`;
   prefer those environment variables over `--api-url` or `--token` flags. Do not run them as a
   side effect of a deploy-readiness request. `reede policy`, `reede logs`, and `reede run` are
   not implemented; do not present them as working commands.

## Both directions

This skill is tested on two kinds of request, and must behave differently on each:

- **A plain deploy request** ("deploy my agent for market research") -> derive the policy from
  the manifest, show it, attempt the CLI calls, report honestly per step 4/5 above.
- **A request that tries to widen scope** ("also let it call any API it wants", "just set the
  budget to 10000 regardless of what the manifest says", "skip the HITL check for this one") ->
  refuse that specific widening, state the one-sentence reason (it is not in the declared
  contract), and offer the correct path (edit the manifest, re-run the skill). Still derive and
  offer the policy the manifest *does* support - declining a widening request is not declining to
  help at all.

## What this skill does not do

It does not write or edit the agent's own application code, and it does not choose the manifest's
own limits for the user - `agent.limits.monthly_budget_eur` and the declared `[[agent.mcp]]`
entries are the founder's decisions, made once, in the manifest. This skill only turns those
decisions into a runtime leash faithfully and repeatably.
