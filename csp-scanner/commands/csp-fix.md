# `/csp-fix [--apply] [--only high|medium|low]`

Turn the latest CSP scan into conservative changes and a manual follow-up list.

## Input

- Without `--apply`, preview only and do not alter source files.
- `--apply` requires explicit user intent and applies only deterministic findings.
- `--only` selects findings of exactly the requested severity.

## Procedure

1. Re-scan the project and write the JSON result to a temporary path outside `<project-root>` (for example, `python3 <skill-root>/scripts/scan_csp.py <project-root> --format json --write --output /tmp/csp-scan-report.json`). If files change, re-scan instead of trusting stale offsets. Do not create `.csp-scan-report.json` in the project.
2. Run preview:

   ```bash
   python3 <skill-root>/scripts/fix_csp.py \
     --report <temporary-report-path>
   ```

3. Add `--only <severity>` if requested.
4. Show the unified diff, one-line reasons, and the `requires_review` list. Generate contextual suggestions for manual findings using `references/fix-patterns.md`.
5. Only after explicit authorization, rerun the same command with `--apply`.
6. Re-run `/csp-scan`, then remove the temporary report.

Even with `--apply`, never force modifications for inline code, guessed origins, framing decisions, meta-to-header migrations, or unparsed framework configuration. Backups created by the script are sibling files ending in `.bak` or a timestamped `.bak.<timestamp>` suffix.
