---
id: path-traversal-unvalidated-file-path
vuln_classes: [path-traversal]
cwe: [CWE-22]
depth_tier: L1
stacks: [node, python, php, go]
fix_patterns:
  - stack: generic
    tier: mechanical
    guidance: Resolve the joined path to its canonical absolute form and reject it unless it is inside the intended base directory; compare resolved paths, not the strings that produced them.
  - stack: generic
    tier: guided
    guidance: Prefer not accepting paths at all — take an opaque identifier and look up the real filename in a database or fixed map, so the caller never names a path.
  - stack: node
    tier: guided
    guidance: Normalize before validating, and treat the decoded form as the input — a check applied before URL decoding can be bypassed by encoding the traversal sequence.
references:
  - https://cwe.mitre.org/data/definitions/22.html
  - https://owasp.org/www-community/attacks/Path_Traversal
  - https://github.com/tanviet12/vbsec
provenance:
  pack: vbsec
  upstream_commit: 1b86c27936d350d1a9ca67f044341262d4219d4e
---

## Detection

A request-supplied value is joined onto a directory and used to open, read, write, serve or delete a file. The join is usually unremarkable path concatenation; the problem is that the caller's segment can climb out of the base directory with parent-directory references, or escape it entirely by being an absolute path, which most join functions honour by discarding the base.

## Verification

Read the order of operations. Validation that happens before normalization and decoding can be defeated, so confirm the check applies to the final resolved path. Confirm the check compares canonical absolute paths against the base directory rather than searching the input for suspicious substrings. Then establish what the sink does — read, write or delete — since that sets the impact, and whether symlinks inside the base directory could redirect a path that passes the check.

## Defensive use

Proves that a caller can name files outside the directory the endpoint was meant to expose: on a read sink, retrieving application source, configuration and credential files; on a write or delete sink, altering files the application has permission to change. Verify it statically by confirming the untrusted segment reaches a filesystem call and that no canonical-path containment check is applied after normalization and decoding. The fix is to resolve the path and reject anything outside the base directory; better, accept an opaque identifier and resolve it to a filename yourself so no caller-supplied path reaches the filesystem.
