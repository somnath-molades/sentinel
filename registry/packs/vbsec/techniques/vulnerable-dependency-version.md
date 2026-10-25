---
id: vulnerable-dependency-version
vuln_classes: [vulnerable-dependency, supply-chain]
cwe: [CWE-1395, CWE-1104]
depth_tier: L0
stacks: [node, python, php, go, generic]
fix_patterns:
  - stack: node
    tier: mechanical
    guidance: Upgrade the package to the first release that carries the fix and commit the updated lockfile, so every install resolves to the patched version.
  - stack: python
    tier: mechanical
    guidance: Pin the fixed version in the requirements or project file and regenerate the lock or constraints file; an unpinned range silently reintroduces the vulnerable version.
  - stack: generic
    tier: guided
    guidance: When no fixed release exists, decide between removing the dependency, vendoring a patched copy, or blocking the vulnerable code path, and record which was chosen and why.
references:
  - https://cwe.mitre.org/data/definitions/1395.html
  - https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
  - https://github.com/tanviet12/vbsec
provenance:
  pack: vbsec
  upstream_commit: 1b86c27936d350d1a9ca67f044341262d4219d4e
---

## Detection

A declared dependency resolves to a version with a published advisory. Read the lockfile rather than the manifest: the manifest states a range, the lockfile states what is actually installed, and the two disagree often. Transitive dependencies matter as much as direct ones and only appear in the lockfile. An absent lockfile is itself a finding, because the installed version is then whatever the registry served most recently.

Files to read, manifest first for intent and lockfile for truth:

- node: `package.json` against `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` or `bun.lockb`
- python: `pyproject.toml`, `requirements*.txt` or `Pipfile` against `poetry.lock`, `uv.lock`, `Pipfile.lock` or a pip-compiled `requirements.txt` with pinned versions and hashes
- php: `composer.json` against `composer.lock`
- go: `go.mod` against `go.sum`
- generic: container base-image tags in a `Dockerfile`, and pinned action versions in CI workflow files, which are dependencies that no language lockfile covers

Version-range markers in a manifest that mean the lockfile is the only source of truth: `^`, `~`, `>=`, `*`, `latest`, an unpinned `main` or branch reference for a git dependency, and a container tag such as `latest` or a bare major version.

## Verification

Compare the resolved version in the lockfile against the advisory's affected range, not against the latest release — being behind is not the same as being vulnerable. Then check whether the vulnerable functionality is reachable: a parser flaw in a package used only by a build script that never sees untrusted input is a lower-priority finding than the same flaw in a request-handling path. Record both the resolved version and the advisory identifier so the conclusion can be rechecked later.

## Defensive use

Proves that a known, publicly documented flaw is present in code this project ships, with an advisory an attacker can read as easily as the maintainers can. Verify it statically by reading the lockfile for the resolved version, matching it against the advisory's affected range, and tracing whether the affected API is called from a path that handles untrusted input. The fix is to upgrade to the first patched release and commit the updated lockfile; where no patch exists, remove or replace the dependency, or prove and document that the vulnerable path is unreachable.
