---
name: csp-scanner
description: Scan project code and deployment configuration for Content Security Policy (CSP) coverage and security risks, then preview or apply conservative fixes. Use for CSP audits, security-header hardening, unsafe-inline or unsafe-eval removal, missing CSP checks, “扫描 CSP 问题”, “检查 CSP 配置”, and “修复 CSP 安全问题”. Do not use for runtime CSP violation-report analytics or non-Web WebView policies.
---

# CSP Scanner

Audit CSP statically and make the smallest safe change in the configuration already used by the project. Treat a missing policy as a security finding, not as a clean scan.

## Safety boundaries

- Prefer a response header over an HTML `meta` policy. A meta policy cannot enforce every directive, including `frame-ancestors`.
- Reject bare `*`, `'unsafe-inline'`, and `'unsafe-eval'` as hardened-policy endpoints. Do not remove them automatically when doing so may break scripts or styles.
- Prefer external files first, then per-response nonces for dynamic content, then hashes for stable inline content. Do not add a static nonce.
- Require an explicit `object-src 'none'`, an explicit `frame-ancestors` policy, and a restrictive `base-uri` such as `'self'` or `'none'`.
- Never broaden a source list to make a page work. Record the required origin precisely and ask for evidence when it is unclear.
- Treat preview as the default. Apply source changes only when the user invokes `/csp-fix --apply` or otherwise explicitly authorizes applying them.
- Even in apply mode, skip findings marked `requires_review`. List them separately with the decision the user must make.

## Commands

Interpret the following user input as commands even when the host does not provide native slash-command registration:

- `/csp-scan [path]`: follow [commands/csp-scan.md](commands/csp-scan.md). Scan only; source and configuration files must remain unchanged.
- `/csp-fix [--apply] [--only high|medium|low]`: follow [commands/csp-fix.md](commands/csp-fix.md). Preview by default; apply only deterministic changes when explicitly requested.

Natural-language requests map to the same workflows. “Scan/check/audit CSP” means scan. “Fix/harden the CSP” means fix, still in preview mode unless application was explicitly requested.

## Scan workflow

1. Read [references/scan-targets.md](references/scan-targets.md) to choose relevant files and understand static-analysis limits.
2. Run `python3 <skill-root>/scripts/scan_csp.py <project-path>`. It writes `.csp-scan-report.json` in the scanned root and prints a Markdown summary. Pass `--no-write` if the user forbids even a report artifact.
3. Use [references/pitfalls.md](references/pitfalls.md) to interpret findings. Inspect any `unparsed-configuration` context manually rather than assuming it is safe.
4. Report each issue in a Markdown table with file, line, severity, problem, and suggested fix. If `detected` is false, state exactly: `未检测到 CSP 配置`.
5. Mention static-analysis blind spots that are relevant to the project. Do not claim runtime enforcement was verified.

## Fix workflow

1. Read `.csp-scan-report.json`; if it does not exist or is stale, run the scan first.
2. Read [references/fix-patterns.md](references/fix-patterns.md) and classify each finding as deterministic or `requires_review`.
3. Run `python3 <skill-root>/scripts/fix_csp.py --report <project-root>/.csp-scan-report.json`, adding `--only <severity>` when requested.
4. Present the unified diff and one short reason per changed policy. Do not edit files in preview mode.
5. With explicit apply authorization, rerun with `--apply`. The script validates source spans, creates a sibling backup, and applies only deterministic changes.
6. Re-scan, then show a before/after checklist and a separate manual follow-up list.

When a framework-specific nonce or hash implementation is required, inspect how responses, templates, static generation, and caching work before proposing code. A nonce must be unpredictable, unique per response, present in both the CSP header and matching elements, and handled safely by caches.

## Output contract

Use this scan table shape:

| 文件 | 行号 | 风险等级 | 问题描述 | 建议修复方式 |
|---|---:|---|---|---|

Use unified diff for previews. Follow it with:

- applied or proposed deterministic changes;
- skipped changes and why they require review;
- validation performed and remaining uncertainty.

For directive semantics or fallback behavior needed during manual review, read [references/directives.md](references/directives.md). For installation and cross-agent discovery, read [references/installation.md](references/installation.md).
