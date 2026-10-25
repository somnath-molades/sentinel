> This document is not legal advice and is pending review by qualified counsel.

# Acceptable use

Sentinel is a defensive tool. Use it to find and fix weaknesses in code you own or are authorized to assess.

## Allowed

- Scanning your own code, or code you have permission to assess.
- Scanning a client's or employer's code under an agreement that covers it.
- Reading findings, explanations and proposed fixes to improve that code.

## Not allowed

- Scanning code or repositories you are not authorized to assess.
- Using Sentinel's output to attack, disrupt or gain access to systems you do not own or are not authorized to test.
- Removing, bypassing or tampering with the scope limit or the authorization attestation, or helping others do so.
- Contributing weaponized proof-of-concept payloads to this repository. Technique entries carry detection and fix guidance only. Contributions that add working exploit payloads will be rejected.

## Why the tool is strict

Sentinel is read-only and refuses any target that is not a local filesystem path or a GitHub repository your `gh` login can access. These limits are part of the design, and they are what keep a defensive tool defensive. Changes that widen them need explicit maintainer review.

If you see misuse of the project, report it as described in `SECURITY.md`.
