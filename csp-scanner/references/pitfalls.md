# CSP risk rules

The scanner emits stable rule identifiers so a report can be consumed by the fixer or another tool.

| Rule | Default severity | Meaning | Automatic action |
|---|---|---|---|
| `unsafe-inline` | High for script/default sources; medium for style-only use | Inline execution weakens CSP and can turn injection into execution | Never remove automatically |
| `unsafe-eval` | High | Enables string-to-code execution in affected script contexts | Never remove automatically |
| `wildcard-source` | High | A directive contains a bare `*` source | Never narrow automatically without origin evidence |
| `missing-object-src` | Medium | No explicit `object-src`; plugins inherit a broader fallback | Add `object-src 'none'` when the literal policy can be edited safely |
| `object-src-not-none` | High | `object-src` permits a source other than `'none'` | Requires compatibility review |
| `missing-frame-ancestors` | Medium | No explicit framing policy | Requires an embedding decision; prefer a response header |
| `missing-base-uri` | Medium | Injected `<base>` elements are not explicitly constrained | Requires checking legitimate base URL behavior |
| `weak-base-uri` | High | `base-uri` contains broad or active sources | Requires checking legitimate base URL behavior |
| `meta-frame-ancestors` | High | A meta-delivered policy cannot enforce `frame-ancestors` | Move or supplement the policy with a response header |
| `report-only` | Low | A report-only policy was found without proof of enforcement | Verify an enforcing policy is also delivered |
| `unparsed-configuration` | Low | A CSP-related configuration marker was found but no complete literal was parsed | Inspect the local framework/configuration context |

## Classification notes

- A source token must be exactly `*` to count as a bare wildcard. Host wildcards such as `*.example.com` still deserve manual review but are not the same rule.
- `'unsafe-inline'` can be ignored by some modern browsers when a valid nonce or hash is present, but its legacy-browser effect and actual directive context still require review. Do not silently downgrade it.
- `default-src` is a fallback for several fetch directives, but `frame-ancestors` and `base-uri` do not fall back to it. This skill still requires an explicit `object-src 'none'` for auditable hardening.
- `frame-src` controls framed content loaded by the page. `frame-ancestors` controls who may embed the page. They are not interchangeable.
- A CSP in HTML is not equivalent to an HTTP response header. In particular, `frame-ancestors`, sandbox, and reporting behavior have delivery constraints.

## Severity overrides

Raise severity when the affected route handles authentication, payments, secrets, administration, or untrusted rich content. Lower severity only with concrete compensating evidence, and record that evidence in the report.
