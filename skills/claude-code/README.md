# Reede skills for Claude Code

`reede-deploy/` is a Claude Code skill (Apache-2.0, ships with Reede's open-core repo) that
teaches a coding agent to deploy-and-govern an agent on Reede: derive a sane leash (budget
ceiling, egress allowlist, HITL threshold) from the agent's own declared manifest contract, then
run the deploy loop.

## Install

Copy the skill directory into your project's `.claude/skills/`:

```bash
cp -r reede-deploy /path/to/your/project/.claude/skills/reede-deploy
```

Claude Code will discover it in your next session. Invoke it by describing what you want in plain
language ("deploy my agent on Reede") - the skill's own description is what triggers it.

See `reede-deploy/SKILL.md` for what it does and does not do.
