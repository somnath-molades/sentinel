> This document is not legal advice and is pending review by qualified counsel.

# Security policy

The project commits to scanning Sentinel with Sentinel in CI and blocking merges on its own findings, so a vulnerability in Sentinel is treated like any other. Today that CI gate only checks that the scan pipeline runs cleanly; blocking merges on findings is committed for a later phase and is not yet in place.

## Reporting a vulnerability

Please report privately, not in a public issue or pull request.

- Preferred: use GitHub's private vulnerability reporting on this repository (Security tab, "Report a vulnerability"), if it is enabled.
- Otherwise: [SECURITY CONTACT EMAIL - PLACEHOLDER, TO BE SET BY THE PROJECT OWNER]

Include what you found, the affected version or commit, steps to reproduce, and the impact you expect. Do not include exploit payloads beyond what is needed to reproduce.

Things we especially want to hear about: any way to make Sentinel accept a target outside its scope limit, skip the authorization attestation, write to or execute anything in a scanned target, or open a network connection to it.

## Response commitment

- Acknowledgement within [ACKNOWLEDGEMENT TIME - PLACEHOLDER, TO BE SET BY THE PROJECT OWNER].
- An initial assessment within [ASSESSMENT TIME - PLACEHOLDER, TO BE SET BY THE PROJECT OWNER].
- Fix handling and disclosure timeline: [FIX AND DISCLOSURE POLICY - PLACEHOLDER, TO BE SET BY THE PROJECT OWNER].
- Reporter credit: [CREDIT POLICY - PLACEHOLDER, TO BE SET BY THE PROJECT OWNER].

[PROJECT STATUS AND NATURE OF THESE COMMITMENTS - PLACEHOLDER, TO BE SET WITH COUNSEL]

## Supported versions

[SUPPORTED VERSIONS - PLACEHOLDER, TO BE SET BY THE PROJECT OWNER]
