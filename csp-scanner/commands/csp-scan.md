# `/csp-scan [path]`

Scan a path for CSP configuration and risks without changing application or infrastructure source files.

## Input

- `path` is optional and defaults to the current project root.
- Reject a path that does not exist or is not a directory.
- Use `--no-write` when the user forbids creation of the `.csp-scan-report.json` report artifact.

## Procedure

1. Resolve the skill root from the directory containing `SKILL.md`.
2. Run:

   ```bash
   python3 <skill-root>/scripts/scan_csp.py <path>
   ```

3. Parse the JSON report at `<path>/.csp-scan-report.json`. The source tree is not modified; this report is the only default artifact.
4. Inspect every `unparsed-configuration` finding in local context.
5. Present the Markdown table required by `SKILL.md`, preserving relative paths and line numbers.

If no policy or configuration marker is found, print `未检测到 CSP 配置` prominently. Do not describe it as “0 issues” or “passed”.

The scan is static. State that response headers, proxies/CDNs, route coverage, browser parsing, and runtime violations were not dynamically verified.
