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

## Verification

Determine whether the setting is literal or environment-driven. A literal true is a finding; a value read from the environment shifts the question to deployment configuration, which the code alone cannot answer — say so rather than guessing. For error echoing, read from the exception handler back to the response serializer and confirm that the exception's own message or trace, rather than a fixed string, reaches the response.

## Defensive use

Proves that the application hands an unauthenticated caller a description of its own internals — file paths, framework and library versions, SQL fragments, and sometimes credentials in connection-string errors — which is the reconnaissance step that makes every other finding cheaper to exploit. Verify it statically by checking whether the debug flag is a literal or environment-driven, and by reading the path from exception handler to response to see whether exception text is serialized out. The fix is a secure-by-default environment-driven flag plus a single error handler that logs detail server-side and returns a generic message with a correlation id.
