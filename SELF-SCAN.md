# Sentinel self-scan

Sentinel scanned by Sentinel. This is the project's primary credibility argument (spec section 10), so it reports what happened, including what is wrong.

## Read this first: this scan cannot find anything

**This phase has no hunter agents. No detection runs.** Sentinel selects which techniques apply to a codebase and then reports; nothing yet applies them. The scan below found zero findings **by construction, not because the code is clean.** Zero findings here is not evidence of anything about Sentinel's security, and an empty report from this build is never a clean result for any target. The tool says so in every report it prints.

What the self-scan does demonstrate is narrower: the pipeline (consent, scope lock, attestation, walk, profile, technique selection, report) runs end to end on a real, non-trivial repository without crashing, and reports its own coverage gaps. It becomes a finding gate in Phase 2, when hunter agents exist.

## Run

| | |
|---|---|
| Date | 2026-10-25 |
| Based on commit | `2b6d102` (plus this file, uncommitted at scan time) |
| Sentinel version | 0.1.0 |
| Mode | pure-reasoning (no dependency CVE detection, no entropy-based secret scanning; this build has no external toolchain) |
| Command | `sentinel init <repo>` then `sentinel scan <repo>`, from a directory outside the repository; exit 0 |
| Files scanned | 170 (24 not scanned, listed below) |

The counts come from a local working tree. It held untracked review artifacts under `.superpowers/`, which a CI checkout does not, so CI numbers differ slightly. The scan was attested by the maintainer for this repository.

## Findings by band

| Band | Count |
|---|---|
| Confirmed | 0 |
| Needs review, not confirmed | 0 |
| Disproved by verification | 0 |

See the first section for why these are zeros.

## What the profile detected

- Languages: TypeScript (53 files), JavaScript (5), shell (1).
- Frameworks, auth libraries, data layers, IaC, client boundary: none. CI: `github-actions`.
- Technique selection: `node`, 12 techniques, exact coverage. No technique stack exists for `shell`, so the one shell script is not examined by stack-specific techniques.

**A defect this document caught.** The first self-scan reported Sentinel's framework as `express`. Sentinel does not use Express. Stack detection matched manifests by basename anywhere in the tree, so it read the `package.json` of the vulnerable-Express test fixture under `tests/fixtures/`. That also switched on Express route extraction for the whole repository. Fixed in `detect-stack.ts`: manifests under a `fixtures` or `__fixtures__` directory no longer declare the stack. Known limit: a genuine application kept in a directory literally named `fixtures` would be under-reported. Fixture code is still walked and counted; only its manifests are ignored.

## Coverage: what was not scanned

- Symlinks not followed (2): both are test fixtures for the scope lock. Neither is an in-tree link that hides project code.
- Too large (2), not UTF-8 (2), minified (5, including the `tsbuildinfo` files): local review artifacts and test fixtures.
- Vendored (5): `node_modules` directories. Generated (6): `dist` build output and `pnpm-lock.yaml`.
- Binary (2): fixture files.

Dependencies were not checked for known vulnerabilities (no CVE tooling in this build). Pinned versions are exact, but nothing here has audited them.

## Open items

Fourteen tasks of review deferred roughly 90 minor findings. They are tracked in the phase's review notes and are not repeated here; they are open, not resolved. Two were flagged must-fix before merge:

1. **False "nothing was missed" claim.** The coverage text for skipped symlinks says that a link pointing inside the scanned folder was examined and "nothing was missed". That is not always true: the link's target can carry its own skip reason (vendored, too large, generated). The text overstates.
2. **Prototype-member lookup on untrusted input.** A language lookup indexes a plain object with an untrusted key, so `__proto__` or `constructor` returns a prototype member. It is not exploitable, because a vocabulary check refuses the value first. It is inconsistent with the `Object.hasOwn` pattern this repository uses elsewhere, and it is a pattern Sentinel itself would flag.

Other known limits of this phase: no hunter agents (above); no CVE or secret-entropy tooling; stacks without techniques (such as shell) are not examined; the CI self-scan asserts that the pipeline exits 0 and is not a finding gate.
