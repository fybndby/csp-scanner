# `/csp-fix [--apply] [--only high|medium|low]`

Turn the latest CSP scan into conservative changes and a manual follow-up list.

## Input

- Without `--apply`, preview only and do not alter source files.
- `--apply` requires explicit user intent and applies only deterministic findings.
- `--only` selects findings of exactly the requested severity.

## Procedure

1. Locate `<project-root>/.csp-scan-report.json`. If missing, run `/csp-scan` first. If files changed after the report, re-scan instead of trusting stale offsets.
2. Run preview:

   ```bash
   python3 <skill-root>/scripts/fix_csp.py \
     --report <project-root>/.csp-scan-report.json
   ```

3. Add `--only <severity>` if requested.
4. Show the unified diff, one-line reasons, and the `requires_review` list. Generate contextual suggestions for manual findings using `references/fix-patterns.md`.
5. Only after explicit authorization, rerun the same command with `--apply`.
6. Re-run `/csp-scan` and show a before/after checklist.

Even with `--apply`, never force modifications for inline code, guessed origins, framing decisions, meta-to-header migrations, or unparsed framework configuration. Backups created by the script are sibling files ending in `.bak` or a timestamped `.bak.<timestamp>` suffix.
