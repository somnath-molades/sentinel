---
id: reflected-xss-unescaped-output
vuln_classes: [xss]
cwe: [CWE-79]
depth_tier: L1
stacks: [node, python, php, generic]
fix_patterns:
  - stack: generic
    tier: mechanical
    guidance: Render the value through the template engine's default escaping path and delete the raw or unescaped marker; escaping must match the context the value lands in, since HTML-escaping does not make a value safe inside a script block, an attribute name or a URL.
  - stack: node
    tier: guided
    guidance: Where markup from users is a product requirement, run it through a maintained sanitizer with an allowlist of elements and attributes, server-side, and store the sanitized form rather than sanitizing on each render.
  - stack: generic
    tier: design-change
    guidance: Add a Content-Security-Policy that disallows inline script, so a missed sink elsewhere fails to execute. This is defence in depth, not a substitute for escaping the sink you found.
references:
  - https://cwe.mitre.org/data/definitions/79.html
  - https://owasp.org/www-community/attacks/xss/
  - https://github.com/tanviet12/vbsec
provenance:
  pack: vbsec
  upstream_commit: 1b86c27936d350d1a9ca67f044341262d4219d4e
---

## Detection

A value that came from the request is written into a response document without escaping for the context it lands in. On the server this is a template rendered with the engine's raw or unescaped marker, or a response body assembled by string concatenation and sent with an HTML content type. On the client it is an assignment to an API that parses its input as markup rather than setting text.

Named sinks to search for:

- browser DOM: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `document.writeln`, `Range.createContextualFragment`, `DOMParser.parseFromString` followed by insertion, and `eval`, `setTimeout` or `setInterval` given a string
- react: `dangerouslySetInnerHTML`, and an `href` or `src` prop assigned a request-derived value that may carry a script scheme
- vue: `v-html`; angular: `bypassSecurityTrustHtml` and the other `bypassSecurityTrust*` calls
- server templates: Jinja2's `|safe` and `Markup()`, Django's `|safe` and `mark_safe`, Handlebars' and Mustache's triple-brace form, EJS's `<%-`, Go's `template.HTML` conversion, Twig's `|raw`, Blade's `{!! !!}`, and PHP's `echo` of request data into markup
- framework-level: a response written with an HTML content type and a body assembled by concatenation rather than rendered through a template

The paired safe forms worth recognising: `textContent` and `innerText`, React's and Vue's default interpolation, and the double-brace or `<%=` escaping form of each template engine. In a framework that escapes by default, a finding is only real through one of the escape hatches listed above; absent one, do not report it.

## Verification

Read from the sink backwards to the value's origin and confirm it is request-derived. Then determine the context precisely: text node, attribute value, URL attribute, inline script, or style — because the correct escaping differs for each and a value escaped for the wrong one is still exploitable. Check whether any sanitization is a maintained allowlist sanitizer or an ad-hoc pattern replacement, and note the difference, as pattern replacement is routinely bypassable.

## Defensive use

Proves that an attacker can run script in another user's browser session on this origin, which in practice means acting as that user against this application — reading the page, issuing authenticated requests, and taking any action the session permits. Verify it statically by identifying the sink, reading backwards to a request-derived origin, and establishing the exact output context so the required escaping is unambiguous. The fix is context-correct escaping on the default rendering path; where user markup is required, an allowlist sanitizer applied server-side, with a script-restricting Content-Security-Policy as a second layer.
