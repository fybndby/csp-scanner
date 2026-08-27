# Cross-agent installation

Keep this `csp-scanner/` directory as one authoritative package. Do not maintain divergent copies of `SKILL.md`.

## Recommended project layout

Copy the package to the vendor-neutral location:

```text
<project>/.agents/skills/csp-scanner/SKILL.md
```

- Codex discovers project skills from `.agents/skills/`.
- Current OpenCode versions also discover `.agents/skills/`, so a second OpenCode copy is unnecessary. OpenCode additionally accepts `.opencode/skills/`.
- For Claude Code installations that do not discover `.agents/skills/`, copy the same package to `.claude/skills/csp-scanner/` or create a relative symlink to the authoritative directory.

Example symlink from the project root:

```bash
mkdir -p .claude/skills
ln -s ../../.agents/skills/csp-scanner .claude/skills/csp-scanner
```

If symlinks are unreliable on the target OS or CI checkout, copy the directory during project bootstrap and overwrite it only from the authoritative package. Never edit the generated copy directly.

## OpenCode verification

OpenCode's current official skill documentation lists all three project sources: `.opencode/skills`, `.claude/skills`, and `.agents/skills`. Verify discovery after upgrading OpenCode because tool behavior can change:

1. Start OpenCode inside the project worktree.
2. Confirm `csp-scanner` appears in the available skills.
3. Invoke `扫描一下这个项目的 CSP 问题` and `/csp-scan`.

Official reference: <https://opencode.ai/docs/skills/>

## Command portability

The `commands/` files define behavior shared by all hosts. Native slash-command registration differs by product and version, so `SKILL.md` explicitly tells the agent to interpret `/csp-scan` and `/csp-fix` as skill commands even when the host has no separate slash-command registry.
