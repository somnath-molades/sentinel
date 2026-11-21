---
id: permissive-cors-with-credentials
vuln_classes: [cors-misconfiguration, insecure-configuration]
cwe: [CWE-942, CWE-346]
depth_tier: L0
domain: authorization
stacks: [node, python, php, generic]
fix_patterns:
  - stack: generic
    tier: mechanical
    guidance: Replace the reflected or wildcard origin with an allowlist of exact origins, and echo back only an origin found in that list.
  - stack: generic
    tier: design-change
    guidance: If the API genuinely needs to serve many unpredictable origins, stop authenticating it with cookies; use a bearer token the caller must attach deliberately, so a cross-origin page cannot authenticate as the user implicitly.
references:
  - https://cwe.mitre.org/data/definitions/942.html
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
  - https://github.com/tanviet12/vbsec
provenance:
  pack: vbsec
  upstream_commit: 1b86c27936d350d1a9ca67f044341262d4219d4e
---

## Detection

The CORS configuration pairs a permissive origin with credentialed requests. Two shapes carry the risk: the allowed origin is the wildcard while the credentials flag is also enabled, or — more commonly, because the wildcard plus credentials combination is rejected by browsers — the server reads the request's own `Origin` header and echoes it back as the allowed origin, which allows any site while satisfying the browser's rule. Over-broad matching counts too: a check that accepts any origin merely *containing* the company domain accepts an attacker-registered lookalike.

Named settings and sinks to search for:

- headers written directly: `Access-Control-Allow-Origin` set to `*`, or set from `req.headers.origin`, `request.headers.get("Origin")`, `$_SERVER['HTTP_ORIGIN']` or `r.Header.Get("Origin")`; paired with `Access-Control-Allow-Credentials: true`
- node: the `cors` middleware configured with `origin: true`, `origin: "*"`, a reflecting `origin` callback, or a loosely matched regular-expression `origin`, together with `credentials: true`
- python: `CORS_ALLOW_ALL_ORIGINS = True` or `CORS_ORIGIN_ALLOW_ALL = True` in django-cors-headers with `CORS_ALLOW_CREDENTIALS = True`; FastAPI's `CORSMiddleware` with `allow_origins=["*"]` or `allow_origin_regex` plus `allow_credentials=True`
- php: a `header('Access-Control-Allow-Origin: ' . $_SERVER['HTTP_ORIGIN'])` call, and Laravel's `cors.php` with `allowed_origins` set to `*` and `supports_credentials` true
- bypassable matching to look for in any of the above: `startsWith`, `endsWith`, `includes`, `in`, `strpos`, or a regular expression with an unanchored or unescaped domain

## Verification

Read the origin decision itself. If the allowed-origin value derives from the incoming request in any way, the allowlist is not an allowlist. Check how the match is done — substring and `endsWith` checks against a domain are bypassable by registering a domain with that suffix, while an exact set membership test is not. Then confirm credentials are actually in play: look for the credentials flag being enabled, or for session authentication by cookie, since without credentials the misconfiguration leaks much less.

## Defensive use

Proves that a page on any origin an attacker controls can make authenticated requests to this API in a logged-in victim's browser and read the responses, turning every authenticated endpoint into one the attacker can reach without ever stealing a token. Verify it statically by reading the origin decision for derivation from the request and for substring rather than exact matching, and by confirming cookie or credentialed authentication is in use. The fix is an exact-match allowlist of known origins; where the origin set cannot be known in advance, move off implicit cookie authentication to a bearer token the caller must attach explicitly.
