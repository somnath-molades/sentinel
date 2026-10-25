# Sentinel

Defensive security scanning for code you own.

Sentinel is being built as a plugin for LLM coding harnesses. It walks a repository you control, works out what it is looking at, selects the security techniques that apply, and reports in language a non-specialist can act on — what the problem is, what someone could do with it, and what to change.

---

## Read this before trying it

**This build cannot find vulnerabilities.** The detection layer — the agents that actually hunt — is the next phase of work. What exists today selects which techniques *would* apply to a codebase and reports honestly on its own coverage. Every scan says so, in every report it prints.

So: zero findings from Sentinel today means **nothing was examined**, not that your code is clean. The tool states that itself rather than leaving you to infer it, and [`SELF-SCAN.md`](SELF-SCAN.md) — Sentinel scanned by Sentinel — opens with the same warning.

That honesty is the point rather than an apology for an early version. A security tool that reports zero findings is making the least believable claim available to it, so this one is built to distinguish *examined and clean* from *never examined* at every layer: in the report, in the SARIF output, and in the exit code.

## What works today

| | |
|---|---|
| **Scope enforcement** | Accepts a local directory or a GitHub repository you can access, and refuses everything else — in code, not in a disclaimer |
| **Authorization** | Displays an attestation you must accept by typing, recorded per target, invalidated if the attestation text ever changes |
| **Read-only** | Never writes to, executes, or connects to a target application. The one network operation is a shallow clone of a repository you have access to |
| **Repository profiling** | Languages, frameworks, entrypoints, authorization surfaces, data layer, infrastructure-as-code, CI configuration — computed once, reported with its own gaps |
| **Technique registry** | 13 entries across 2 packs, each required to state what it proves, how to verify it by reading code, and how to fix it |
| **Reporting** | Plain-language markdown and SARIF 2.1.0, both carrying what was *not* examined |

## Install

Not published to npm yet. From source:

```sh
git clone https://github.com/somnath-molades/sentinel.git
cd sentinel
pnpm install
pnpm build
```

Requires Node 20 or later. `gh` must be installed and authenticated only if you intend to scan a GitHub repository rather than a local path.

## Use

```sh
# Attest that you are authorized to assess this target. Required once per target.
node packages/cli/dist/bin.js init /path/to/your/project

# Scan it
node packages/cli/dist/bin.js scan /path/to/your/project
```

`init` shows you [`AUTHORIZATION.md`](AUTHORIZATION.md) and asks you to type `yes`. Sentinel refuses to scan a target you have not attested.

Useful flags:

```sh
scan <target> --format sarif      # SARIF 2.1.0 on stdout, pipeable
scan <target> --max-files 500     # stop walking after n files
packs list                        # what is in the technique registry
packs audit                       # validate the registry
```

`--fail-on <band>` exists but **exits 2 on every invocation in this build**, because a severity gate cannot be evaluated without a detection layer. Exiting 0 would be a green light wired to nothing.

## Scope and authorization

Sentinel is for code you own or are authorized to assess. That is enforced rather than requested: the tool accepts a local filesystem path or a GitHub repository your authenticated account can read, and refuses anything else. You attest authorization per target before anything is read.

The scope lock narrows what Sentinel will do. It does not prove you are authorized — that remains your responsibility, and the terms are explicit about it. See [`AUTHORIZATION.md`](AUTHORIZATION.md), [`ACCEPTABLE-USE.md`](ACCEPTABLE-USE.md) and [`TERMS.md`](TERMS.md).

**The legal documents are not finished.** Each states on its first line that it is pending review by qualified counsel, and several carry unfilled placeholders. Treat them as drafts.

## Technique registry

Security knowledge lives in markdown, not in code, so it can be contributed by pull request. Each entry declares the vulnerability classes it addresses, the stacks it applies to, how to detect it, how to verify it statically, and stack-specific fixes.

Every entry must carry a **defensive use** section stating what the technique proves, how to verify it by reading code, and what the fix is. An entry without it fails validation. That requirement is how knowledge drawn from offensive security tooling stays defensive here — enforced by schema rather than by convention.

Upstream sources and their licences are recorded in [`registry/AUDIT.md`](registry/AUDIT.md). Nine of eleven intended sources have been audited; two could not be located.

## Honesty about this repository

| | |
|---|---|
| [`SELF-SCAN.md`](SELF-SCAN.md) | Sentinel's report on itself, including a defect that report caught |
| [`docs/PHASE-1-DEFERRED.md`](docs/PHASE-1-DEFERRED.md) | 105 open findings from the phase's own reviews |
| [`docs/PHASE-1-RULINGS.md`](docs/PHASE-1-RULINGS.md) | 65 decisions taken during the build, each with what it costs if wrong |

Publishing an open backlog of a security tool's own defects is unusual. It is here because a tool asking you to trust its judgment about your code should be legible about its judgment on itself.

## Status

Phase 1 of five. The core, an MCP server and a standalone CLI, with 335 tests. The CLI deliberately exists before any harness plugin — a working standalone command is what demonstrates the core is harness-agnostic rather than merely described that way.

Next: the detection layer. Hunter agents, adversarial verifiers that must survive an attempt to disprove each finding before it is reported, and the explain-and-fix layer that turns a finding into a change you can apply.

## Licence

MIT. See [`LICENSE`](LICENSE) — the copyright holder is still a placeholder.

Reporting a vulnerability in Sentinel itself: [`SECURITY.md`](SECURITY.md).
