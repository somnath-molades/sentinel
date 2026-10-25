---
id: command-injection-shell-interpolation
vuln_classes: [command-injection]
cwe: [CWE-78]
depth_tier: L1
stacks: [node, python, php, go]
fix_patterns:
  - stack: node
    tier: mechanical
    guidance: Use the spawn form that takes the executable and an argument array and does not start a shell, instead of the form that takes one command string.
  - stack: python
    tier: mechanical
    guidance: Pass a list of arguments with shell invocation disabled, so the operating system receives the arguments directly and no shell metacharacter is interpreted.
  - stack: generic
    tier: guided
    guidance: Where a shell is genuinely required, keep the untrusted value out of the command text — pass it through an environment variable or on standard input, and validate it against a strict pattern first.
references:
  - https://cwe.mitre.org/data/definitions/78.html
  - https://owasp.org/www-community/attacks/Command_Injection
  - https://github.com/tanviet12/vbsec
provenance:
  pack: vbsec
  upstream_commit: 1b86c27936d350d1a9ca67f044341262d4219d4e
---

## Detection

A variable is interpolated into a command line that is executed through a shell. The shape to look for is a process-launching call whose argument is a single assembled string rather than an executable plus an argument list — the string form asks the operating system for a shell, and a shell re-parses metacharacters that separate commands, substitute output, or redirect files.

## Verification

Distinguish the two call forms, because they look similar and behave differently: the argument-array form passes values straight through and is not injectable in this way, while the command-string form is. Then trace the interpolated variable to its origin and check for validation on the way. Quoting the value inside the command string is not a fix and should not be read as one; confirm whether any validation is an allowlist of permitted values or a denylist of characters, since denylists miss cases.

## Defensive use

Proves that a caller can run commands of their choosing on the host, in the application's own process context and with its filesystem, network and credential access — the highest-impact outcome in this tier, because it does not stop at the application's data. Verify it statically by identifying the call form, confirming it is the shell-invoking string variant, and tracing the interpolated value back to an untrusted origin without allowlist validation. The fix is the argument-array call form with no shell; if a shell is unavoidable, deliver the value out of band through the environment or standard input, never inside the command text.
