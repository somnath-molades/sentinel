---
id: hardcoded-secret-in-source
vuln_classes: [secret-exposure]
cwe: [CWE-798]
depth_tier: L0
stacks: [node, python, php, go, generic]
fix_patterns:
  - stack: generic
    tier: mechanical
    guidance: Move the value to an environment variable or secret manager, read it at startup, and fail fast when it is missing. Then rotate the exposed credential, because it remains valid until revoked.
  - stack: generic
    tier: guided
    guidance: Purging the value from git history is only worth doing after rotation; treat any secret that reached a shared branch as compromised regardless.
references:
  - https://cwe.mitre.org/data/definitions/798.html
  - https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
  - https://github.com/tanviet12/vbsec
provenance:
  pack: vbsec
  upstream_commit: 1b86c27936d350d1a9ca67f044341262d4219d4e
---

## Detection

A credential is written as a literal in tracked source, configuration or infrastructure files: an API key, database password, private key block, signing secret or cloud access key assigned to a constant, embedded in a connection string, or committed inside a `.env`-style file that is not ignored. High-entropy string literals next to names containing `key`, `token`, `secret`, `password` or `credential` are the common shape, as are provider-specific prefixes and PEM headers.

## Verification

Confirm three things by reading, not by guessing. First, that the literal is a real credential rather than a placeholder, a test fixture or an example from documentation — placeholders are usually repeated across files and obviously structured. Second, that the file is tracked by version control, since an untracked local file is a different and lesser problem. Third, which component the credential grants access to, by following where the constant is used; a signing secret for session cookies has a different blast radius than a read-only analytics key.

## Defensive use

Proves that anyone with read access to the repository — every past and present contributor, every fork, and anyone who obtains a clone — already holds a working credential for the named system, and that rotating it is the only way to take that access back. Verify it statically: locate the literal, confirm it is tracked, and identify the system it authenticates to from its use sites. The fix is to read the value from the environment or a secret manager at startup and fail loudly if absent, and then to rotate the exposed credential; removing the line without rotating leaves the access intact.
