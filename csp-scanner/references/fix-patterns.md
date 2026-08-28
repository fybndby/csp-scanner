# CSP fix patterns

Read this reference before generating or applying fixes.

## Choose the delivery layer first

Use this priority order before changing directives:

1. Update the component that actually returns production responses: application server, reverse proxy, CDN, or hosting platform.
2. For a statically deployed site, use the hosting provider's response-header configuration, such as `_headers`, `vercel.json`, Nginx, Apache, or the equivalent platform setting.
3. Mirror the tested policy in Webpack/Rspack `devServer.headers`, Vite `server.headers`, or Vite `preview.headers` only when local development needs CSP parity. Label this as development/preview configuration.
4. Use `<meta http-equiv="Content-Security-Policy">` only when HTTP response headers truly cannot be configured. Document that it cannot enforce `frame-ancestors` and does not provide equivalent reporting or framing coverage.

`X-Frame-Options` is also an HTTP response header. Putting it in HTML has no effect. Prefer CSP `frame-ancestors` as the primary framing policy; optionally retain a compatible `X-Frame-Options: DENY` or `SAMEORIGIN` response header for legacy defense.

Development-only examples:

```js
// webpack.config.js or rspack.config.js — local development only
export default {
  devServer: {
    headers: {
      'Content-Security-Policy': "default-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self';",
      'X-Frame-Options': 'SAMEORIGIN',
    },
  },
};
```

```js
// vite.config.js — server is dev; preview is local production-build preview
export default {
  server: {
    headers: {
      'Content-Security-Policy': "default-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self';",
      'X-Frame-Options': 'SAMEORIGIN',
    },
  },
  preview: {
    headers: {
      'Content-Security-Policy': "default-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self';",
      'X-Frame-Options': 'SAMEORIGIN',
    },
  },
};
```

Do not insert either example blindly. First derive the policy from the application's actual script, style, image, font, connection, worker, and framing requirements. Production must receive the final policy as an HTTP response header from its real delivery layer.

## Decision classes

### Deterministic

The bundled fixer automatically handles only this current case:

- a complete, literal enforcing policy is available;
- `object-src` is absent; and
- adding `object-src 'none'` does not require rewriting a framework directive object.

The fixer validates the report's source span before editing, does not create backup files, and refuses stale or ambiguous input. Adding more automatic rules requires tests proving both safe selection and safe refusal.

### Requires review

Do not automatically apply these changes:

- removing `'unsafe-inline'` or `'unsafe-eval'`;
- replacing a wildcard or broad scheme with guessed origins;
- choosing a `frame-ancestors` value;
- changing an existing `object-src` or `base-uri`;
- converting a meta policy to a response header;
- treating a development or preview server header as the production fix;
- choosing the application's production response layer when deployment ownership is unclear;
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
