---
id: debug-mode-verbose-errors
vuln_classes: [information-disclosure, insecure-configuration]
cwe: [CWE-489, CWE-209]
depth_tier: L0
stacks: [node, python, php, generic]
fix_patterns:
  - stack: generic
    tier: mechanical
    guidance: Drive the debug flag from the environment with a secure default, so production needs no change to be safe and a developer must opt in to verbose output.
  - stack: generic
    tier: guided
    guidance: Replace per-handler error echoing with one central error handler that logs the exception server-side and returns a generic message plus a correlation id to the client.
references:
  - https://cwe.mitre.org/data/definitions/489.html
  - https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
  - https://github.com/tanviet12/vbsec
provenance:
  pack: vbsec
  upstream_commit: 1b86c27936d350d1a9ca67f044341262d4219d4e
---

## Detection

A debug or development setting is enabled unconditionally in committed configuration, or an error path returns internal detail to the caller. Typical shapes: a framework debug flag set to a literal true, a stack trace or exception message serialized into the HTTP response body, a directory listing or interactive debugger left enabled, or a verbose logger configured to write request bodies containing credentials.

Named settings and sinks to search for:

- python: `DEBUG = True` in Django settings, `app.run(debug=True)` and `app.debug = True` in Flask, `FastAPI(debug=True)`, and Werkzeug's interactive debugger enabled with the evaluating console
- php: `display_errors` set on, `error_reporting(E_ALL)` paired with display, `APP_DEBUG=true` in a committed Laravel `.env`, and Symfony's `APP_ENV=dev`
- node: `NODE_ENV` not set to `production` where the framework keys error verbosity off it, Express's default error handler returning `err.stack`, and an error middleware that puts `err.message` or `err.stack` in the response body
- go: `gin.SetMode(gin.DebugMode)`, and `http.Error(w, err.Error(), ...)` which writes the raw error text to the client
- generic: `JSON.stringify(err)` or an equivalent serialization of an exception object into a response; a directory-listing option enabled on a static file handler; a profiler, metrics or admin endpoint mounted without authentication

The distinction that decides the finding: whether the flag's value is a literal, or read from the environment with a secure default.

## Verification

Determine whether the setting is literal or environment-driven. A literal true is a finding; a value read from the environment shifts the question to deployment configuration, which the code alone cannot answer — say so rather than guessing. For error echoing, read from the exception handler back to the response serializer and confirm that the exception's own message or trace, rather than a fixed string, reaches the response.

## Defensive use

Proves that the application hands an unauthenticated caller a description of its own internals — file paths, framework and library versions, SQL fragments, and sometimes credentials in connection-string errors — which is the reconnaissance step that makes every other finding cheaper to exploit. Verify it statically by checking whether the debug flag is a literal or environment-driven, and by reading the path from exception handler to response to see whether exception text is serialized out. The fix is a secure-by-default environment-driven flag plus a single error handler that logs detail server-side and returns a generic message with a correlation id.
