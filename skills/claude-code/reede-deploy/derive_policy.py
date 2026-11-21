#!/usr/bin/env python3
"""Deterministic leash derivation from a Reede ManifestV1 TOML (M10).

The coding agent using the reede-deploy skill MUST run this script rather than eyeballing the
manifest and inventing numbers - a leash that is "sane" has to be reproducible and auditable, not
a per-run LLM guess. Every number and every allowlist entry below is a pure function of the
manifest's own declared fields; nothing here reads outside the manifest.

Rules (see SKILL.md for the rationale):
  - budget_ceiling_eur: the manifest's own agent.limits.monthly_budget_eur, or a conservative
    default if unset. Never anything the manifest did not itself declare or default to - a policy
    is not allowed to grant MORE than the declared contract, only up to it.
  - hitl_above_credits: 20% of the budget ceiling, floor 10. A fixed, disclosed formula, not a
    judgment call per agent.
  - egress_allowlist: the hostname of every declared [[agent.mcp]] entry that has a `url` (a
    real external dependency). stdio-transport entries (only an `image`, no `url`) declare no
    external host and contribute nothing - a container image name is not a network destination.
    This is the enforcement point for "decline to widen beyond the declared contract": nothing
    can appear in the allowlist that was not a url somewhere in the manifest.

Usage: derive_policy.py <manifest.toml>
Output: policy JSON on stdout.
"""

import json
import sys
from urllib.parse import urlparse

try:
    import tomllib
except ImportError:  # Python < 3.11
    import tomli as tomllib

DEFAULT_BUDGET_CEILING_EUR = 50.0
HITL_FRACTION = 0.2
HITL_FLOOR_CREDITS = 10


def derive_policy(manifest):
    agent = manifest.get("agent", {})
    limits = agent.get("limits", {}) or {}
    mcp_servers = agent.get("mcp", []) or []

    declared_budget = limits.get("monthly_budget_eur")
    budget_ceiling_eur = declared_budget if declared_budget is not None else DEFAULT_BUDGET_CEILING_EUR

    hitl_above_credits = max(HITL_FLOOR_CREDITS, int(budget_ceiling_eur * HITL_FRACTION + 0.999))

    allowlist = set()
    declared_urls = []
    declared_images_no_url = []
    for mcp in mcp_servers:
        url = mcp.get("url")
        if url:
            host = urlparse(url).netloc or url
            allowlist.add(host)
            declared_urls.append({"name": mcp.get("name"), "url": url, "host": host})
        elif mcp.get("image"):
            declared_images_no_url.append({"name": mcp.get("name"), "image": mcp.get("image")})

    return {
        "agent_id": agent.get("id"),
        "policy": {
            "budget_ceiling_eur": budget_ceiling_eur,
            "hitl_above_credits": hitl_above_credits,
            "egress_allowlist": sorted(allowlist),
        },
        "derivation": {
            "budget_ceiling_eur": (
                f"from manifest agent.limits.monthly_budget_eur = {declared_budget}"
                if declared_budget is not None
                else f"manifest declared no monthly_budget_eur; used the conservative default {DEFAULT_BUDGET_CEILING_EUR}"
            ),
            "hitl_above_credits": f"max({HITL_FLOOR_CREDITS}, ceil({budget_ceiling_eur} * {HITL_FRACTION})) = {hitl_above_credits}",
            "egress_allowlist": (
                f"hostnames of {len(declared_urls)} declared [[agent.mcp]] entries with a url field"
                if declared_urls
                else "no [[agent.mcp]] entry declares a url - allowlist is empty (fail closed, per the Reede contract, rule 2: an empty allowlist means nothing allowed, never everything allowed)"
            ),
        },
        "declared_contract": {
            "mcp_with_url": declared_urls,
            "mcp_stdio_no_declared_host": declared_images_no_url,
        },
    }


def main():
    if len(sys.argv) != 2:
        print("usage: derive_policy.py <manifest.toml>", file=sys.stderr)
        sys.exit(1)
    with open(sys.argv[1], "rb") as f:
        manifest = tomllib.load(f)
    print(json.dumps(derive_policy(manifest), indent=2))


if __name__ == "__main__":
    main()
