> This document is not legal advice and is pending review by qualified counsel.

# Security policy

Sentinel scans itself in CI and blocks merges on its own findings. A vulnerability in Sentinel is treated like any other.

## Reporting a vulnerability

Please report privately, not in a public issue or pull request.

- Preferred: use GitHub's private vulnerability reporting on this repository (Security tab, "Report a vulnerability"), if it is enabled.
- Otherwise: [SECURITY CONTACT EMAIL - PLACEHOLDER, TO BE SET BY THE PROJECT OWNER]

Include what you found, the affected version or commit, steps to reproduce, and the impact you expect. Do not include exploit payloads beyond what is needed to reproduce.

Things we especially want to hear about: any way to make Sentinel accept a target outside its scope limit, skip the authorization attestation, write to or execute anything in a scanned target, or open a network connection to it.

## Response commitment

- Acknowledgement within 5 business days.
- An initial assessment (accepted, needs more information, or declined, with reasons) within 14 days.
- Fixes for confirmed issues are prioritized by severity, and we will keep you updated until release.
- With your agreement, we credit you in the release notes. We ask that you give us reasonable time to fix before public disclosure.

These are good-faith targets from a volunteer-run open-source project, not contractual guarantees.

## Supported versions

Only the latest release receives security fixes.
