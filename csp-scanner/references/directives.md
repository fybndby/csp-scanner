# Directive review guide

Use this guide only when manual review needs directive semantics beyond the scanner's stable rules.

## Baseline policy shape

A hardened starting point is contextual, but usually includes:

```text
default-src 'self';
object-src 'none';
base-uri 'self';
frame-ancestors 'none';
script-src 'self' 'nonce-<per-response-value>';
style-src 'self';
```

This is a review baseline, not a string to paste blindly. Add exact origins only when the application demonstrably needs them. Decide whether `frame-ancestors` should be `'none'`, `'self'`, or a documented partner allowlist.

## Important directive groups

- Navigation and document: `base-uri`, `form-action`, `frame-ancestors`, `sandbox`.
- Script: `script-src`, `script-src-elem`, `script-src-attr`, `worker-src`.
- Style: `style-src`, `style-src-elem`, `style-src-attr`.
- Fetch: `connect-src`, `img-src`, `font-src`, `media-src`, `object-src`, `frame-src`, `manifest-src`.
- Reporting: `report-uri` is legacy; `report-to` integrates with the Reporting API but browser support and header setup must be verified.
- Upgrade: `upgrade-insecure-requests` can help migrate HTTP subresources but is not a substitute for correct HTTPS URLs.

## Fallbacks that matter

- `default-src` is the fallback for many fetch directives when their specific directive is absent.
- `script-src-elem` and `script-src-attr` have layered fallback behavior through `script-src` and then `default-src`.
- `frame-ancestors`, `base-uri`, and `form-action` do not inherit from `default-src`.
- A missing directive is not automatically safe merely because a restrictive-looking `default-src` exists; confirm its defined fallback behavior.

## Source expression review

- Prefer `'self'`, exact HTTPS origins, nonces, and hashes.
- A nonce must be freshly generated for each response and unpredictable.
- A hash must cover the exact inline bytes; whitespace changes invalidate it.
- Avoid broad schemes such as `https:` when a finite origin list is available.
- Review `data:` and `blob:` per directive. They are sometimes necessary for images or workers but should not be enabled globally.
- Do not add `'strict-dynamic'` without understanding its browser behavior, nonce/hash prerequisite, and effect on host allowlists.
