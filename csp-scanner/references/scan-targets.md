# Scan targets

Read this reference before scanning or extending the scanner.

## Included targets

The bundled scanner searches text files commonly responsible for CSP:

- application code and templates: `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`, `.py`, `.rb`, `.php`, `.java`, `.kt`, `.go`, `.rs`, `.cs`, `.html`, `.htm`, `.vue`, `.svelte`, `.erb`, `.ejs`, `.hbs`, `.twig`, `.jinja`, `.jinja2`;
- server and hosting configuration: `nginx.conf`, Apache `.conf` and `.htaccess`, `_headers`, `vercel.json`, `netlify.toml`, YAML, JSON, TOML, Terraform, and Kubernetes manifests;
- response-header APIs and configuration keys containing `Content-Security-Policy`;
- build-tool configuration: `webpack*.config.{js,ts,mjs,cjs}`, `vite.config.{js,ts,mjs,cjs}`, and `rspack*.config.{js,ts,mjs,cjs}`;
- Webpack/Rspack `devServer.headers`, Vite `server.headers`, and Vite `preview.headers`, classified separately from production delivery;
- HTML `<meta http-equiv="Content-Security-Policy" ...>`;
- framework markers such as `contentSecurityPolicy`, `securityHeaders`, and Helmet CSP configuration.

It skips dependency, build, cache, VCS, and generated-output directories such as `.git`, `node_modules`, `vendor`, `dist`, `build`, `.next`, `coverage`, and Python caches. Files larger than 2 MiB are skipped by default.

## Interpretation limits

Static text matching cannot prove the effective browser policy. Manually inspect these cases when present:

- policies assembled through concatenation, environment variables, helper functions, or generated infrastructure;
- framework directive objects instead of literal header strings;
- multiple CSP headers, route-specific middleware, redirects, reverse proxies, or CDN overrides;
- report-only policies, which do not enforce restrictions;
- template expressions inside a policy literal;
- policies delivered only in production or injected outside the repository.

Build-tool server options require special interpretation:

- Webpack and Rspack `devServer.headers` apply only when their development server is serving the response.
- Vite `server.headers` applies to the development server; `preview.headers` applies to the local preview server.
- These settings are useful for testing CSP compatibility during development, but they do not configure the production web server, CDN, or static host.
- If one of these is the only detected policy, report that CSP exists locally while production enforcement remains unconfirmed.

An `unparsed-configuration` finding means a likely configuration point was found but a complete literal policy could not be extracted. It is not evidence that the policy is safe.

## Scope boundary

Do not scan runtime CSP violation reports, Electron policies, or mobile WebView behavior under this skill. Do not traverse outside the requested project root through symlinks.
