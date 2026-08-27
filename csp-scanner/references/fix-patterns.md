# CSP fix patterns

Read this reference before generating or applying fixes.

## Decision classes

### Deterministic

The bundled fixer automatically handles only this current case:

- a complete, literal enforcing policy is available;
- `object-src` is absent; and
- adding `object-src 'none'` does not require rewriting a framework directive object.

The fixer validates the report's source span before editing, creates a sibling backup, and refuses stale or ambiguous input. Adding more automatic rules requires tests proving both safe selection and safe refusal.

### Requires review

Do not automatically apply these changes:

- removing `'unsafe-inline'` or `'unsafe-eval'`;
- replacing a wildcard or broad scheme with guessed origins;
- choosing a `frame-ancestors` value;
- changing an existing `object-src` or `base-uri`;
- converting a meta policy to a response header;
- rewriting computed strings, framework objects, generated config, or environment-dependent policies.

## Inline code removal

Use this preference order:

1. Move first-party inline code into an external file served from an already allowed exact origin.
2. For dynamic server-rendered content, generate a cryptographically unpredictable nonce per response. Put the same value in the CSP header and each approved `<script>` or `<style>` element.
3. For stable inline content, compute and declare a CSP hash over the exact bytes.

Before proposing a nonce implementation, trace the response boundary, template rendering, caching/CDN behavior, static generation, error pages, and streaming. Never hard-code or reuse a nonce across responses.

## Wildcards and external origins

Inventory actual network requests and third-party integrations. Replace a bare wildcard with the smallest directive-specific set of exact origins. Do not copy every observed domain into `default-src`; place each origin in the directive that needs it.

## Framing

Choose based on product behavior:

- `'none'` when the page must never be embedded;
- `'self'` when same-origin embedding is required;
- exact partner origins for a documented embedding contract.

Deliver `frame-ancestors` in an HTTP header. If legacy `X-Frame-Options` is present, review the combined behavior rather than assuming one replaces the other everywhere.

## Review output

For each proposal, show a unified diff and one sentence connecting the change to the finding. After apply mode, re-scan and report fixed, remaining, skipped, and newly introduced findings.
