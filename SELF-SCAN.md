# Sentinel self-scan

Sentinel scanned by Sentinel. This is the project's primary credibility argument (spec section 10), so it reports what happened, including what is wrong.

## Read this first: the command-line scan below still cannot find anything

**The `sentinel scan` command runs no hunter.** It selects techniques and reports; it never applies them. The command-line scan in the sections below found zero findings **by construction, not because the code is clean.** Zero findings there is not evidence of anything about Sentinel's security, and an empty report from the command line is never a clean result for any target. The tool says so in every report it prints.

What changed in Phase 2a, stated narrowly:

- Hunter and verifier skills now exist (`skills/sentinel-hunt`, `skills/sentinel-verify`), and the MCP tool `plan_hunts` computes a hunt assignment for each of ten vulnerability domains. These are instructions and plumbing for an agent harness. Nothing in this repository dispatches an agent, so no detection runs unless an operator runs one by hand.
- Only one domain, `injection`, is a proven path: it has the most technique entries (six) and it is the only domain exercised against a fixture with known planted bugs. Nine domains are not proven. Three of them (`iac`, `supply-chain`, `crypto`) have no technique entry at all, so nothing is examined there. The other six (`authorization`, `secrets`, `dependencies`, `agentic`, `memory-safety`, `configuration`) have one or two technique entries each that no real-agent run has ever applied; a technique entry is guidance text, not demonstrated detection. A scan of this repository by Sentinel says nothing about those nine domains.
- The automated tests prove the plumbing with canned agent output. They say nothing about whether a real agent finds bugs; that is measured separately, below, and never asserted by a passing test.

What the command-line self-scan demonstrates is narrower still: the pipeline (consent, scope lock, attestation, walk, profile, technique selection, report) runs end to end on a real, non-trivial repository without crashing, and reports its own coverage gaps. The CI self-scan asserts that and nothing more; it is not a finding gate.

## Real-agent run

One run, 2026-10-25, against `tests/fixtures/targets/express-vulnerable`. Two real agents on Claude Opus 5: one hunter (`hunter-integration-1`) assigned the `injection` domain, and one verifier (`verifier-integration-1`) under a different id. Neither was told what was planted — the fixture's answer-key comments were deliberately removed for this run. Both agents' actual output is archived in `docs/phase-2a-agent-run/`.

Exactly what each agent was given, because it affects what the run proves: its skill file, the `plan_hunts` output for the fixture **pasted in as text by the harness**, and the fixture itself. The hunter was additionally told that over-reporting and under-reporting are both failures and that another agent would try to disprove its output; the verifier was additionally told that `ambiguous` is valid and not to confirm on resemblance. Those instructions restate the skills, but they were in the dispatch as well, so the run does not show that the skill text alone produces this behaviour.

### What it found

| | |
|---|---|
| Planted defects in the `injection` domain | 2 |
| Found | 2 |
| Missed | 0 |
| False positives | 0 |
| Safe counterparts correctly not flagged | 3 |

The hunter reported `src/server.js:23` (a `SELECT` with `req.query.name` concatenated into the statement) and `src/server.js:33` (a `DELETE` with `req.params.id` concatenated), both with a traced reachability claim naming the route and the absence of any binding. It read all five files under the target, not only the one hotspot path. It declined the three parameterized queries, citing the technique's own description of `query(sql, values)` with `$1` as a safe form not to flag, and it declined four other technique classes with stated reasons rather than silent omission — including checking that `src/util.js` is never `require`d before ruling out the cross-file taint technique.

The verifier confirmed both findings after attempting to disprove each (looking for a global `app.use` guard, a sanitizer, a `parseInt` cast, a numeric route constraint, and driver-side binding — all absent). It rated both `exploitability 3, reachability 3, blast_radius 3, data_sensitivity 2`, holding the last at 2 rather than 3 on the explicit ground that the table schema is not in the target, so it could not show that credentials or tokens are among the columns.

### The verifier was also given a deliberately false candidate

The harness injected a third candidate pointing at `src/server.js:28` — the parameterized query the hunter had correctly declined — with a plausible but wrong reachability claim. **This candidate was not produced by the hunter.** It exists because the automated tests can prove a `disproved` verdict travels through the pipeline, but cannot show that a real verifier distinguishes a bound query from an interpolated one.

The verifier disproved it. It identified the line as the technique's own named safe form, tried four ways to rescue the claim (a second concatenated fragment, a disguised template literal, an unbindable identifier such as a table name or `ORDER BY` direction, and an array-form query parameter reaching the statement text) and found none, and additionally caught that the fabricated claim wrongly described the route as unauthenticated when line 27 carries `requireAuth`.

Be careful how much that proves. The injected candidate sat on the form the technique's own prose explicitly names as safe and not to be flagged — the easiest available negative. One disproof of the easiest case is not evidence that the verifier reliably separates a bound value from an interpolated one in harder shapes: a mixed statement where a placeholder elsewhere does not protect an interpolated fragment, an identifier spliced where binding is impossible, or a value bound in one branch and concatenated in another. None of those were tried.

### The most important finding is about Sentinel, not the fixture

The verifier observed that `src/server.js:33` is **also a missing-authorization defect**: an unauthenticated `DELETE /users/:id` removes an arbitrary user by id with no injection involved at all. The fixture makes the contrast explicit, since the adjacent `/sessions/:id` route carries both `requireAuth` and an ownership check returning 403.

That defect was **structurally unreportable in this run.** Only the `injection` hunter was dispatched. The `authorization` domain has two technique entries and `plan_hunts` computes an assignment for it, but no agent was sent to hunt it, so nothing could have reported it. A real defect in Sentinel's own test fixture went unreported — not because an agent missed it, but because this phase ships one proven domain out of ten. Dispatching all ten is Phase 2b's work.

### What this run did not exercise

- **The tool boundary.** The two agents read source with their own file tools; they did not call `record_finding`, `verify_finding` or `report`, because reaching those through `scripts/hunt-integration.mjs` requires an operator attestation, and an automated process must not type a human's authorization statement. The attestation gate refused, which is the gate working as designed. The tool path — ingest validation, the walked-file check, the self-verification refusal, severity merging and both reporters — is covered deterministically by the stubbed-agent loop in `packages/mcp/tests/hunt-loop.test.ts`, with canned candidates and no claim about judgement. To record the tool leg of this run, an operator runs `node packages/cli/dist/bin.js init <target>` themselves and then the runner's `plan` and `run` steps.
- **The skill's own loop.** Because the agents had no MCP session, they never called `plan_hunts` themselves, never joined `registry_root` to a technique `path` to reach the prose, and never read `target_root` to decide what to scan. The harness pasted the assignment in and the agents read the fixture by absolute path. Those three wirings were the point of two fixes in this phase, and they are covered only by tests — this run does not exercise them. An agent that could not locate the technique prose would have looked exactly like an agent that found nothing.
- **The runner itself, on real output.** `scripts/hunt-integration.mjs`'s `run` and scoring path has never executed against real agent output, only against synthetic plumbing inputs. The found/missed/false-positive numbers above were scored by hand from the archived files, not produced by the runner. The runner is not in CI.
- **The self-verification gate, live.** The verifier's id differed from the reporter's, so the refusal never triggered. It is pinned deterministically in the test suite instead.
- **Nine domains.** No hunter ran for any domain but `injection`. Nothing here says anything about the other nine, and the sections above say why three of them cannot report anything at all.
- **Repetition.** This is one run against one small fixture with two planted defects of the same class. It is evidence that the loop can work, not a measurement of how often it does. A single clean result is not a rate.

## Run

**This section is stale against Phase 2a and has not been re-run.** It records a command-line scan from the Phase 1 tree at `2b6d102`. Phase 2a added C and C++ recognition and a C fixture, so the file and language counts below no longer describe HEAD — a measurement of HEAD gives roughly 153 files including TypeScript 60, JavaScript 6, shell 1 and C 2, with a `c` stack that did not exist when this table was written. Re-running it requires an operator attestation, which an automated process must not supply, so the numbers were left as recorded rather than quietly updated to values nobody measured. Treat the table as a Phase 1 artifact.

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

- Languages: TypeScript (53 files), JavaScript (5), shell (1). These 59 are the files with a recognised source language. The other 111 of the 170 scanned files (Markdown documentation, JSON and YAML configuration, registry technique files, fixture data) are walked and counted but carry no language, so no stack is derived from them. Sentinel now prints this share itself: every scan warns how many of the files it walked carry a recognised language and how many were examined by no stack-specific technique.
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

Review across the phase's fourteen tasks deferred 110 minor findings and flagged 2 must-fix before merge. They are listed in full, with where each is and why it was deferred, in [`docs/PHASE-1-DEFERRED.md`](docs/PHASE-1-DEFERRED.md). They are open, not resolved except where that document marks an item closed. The two must-fix items were fixed before merge:

1. **False "nothing was missed" claim (fixed).** The coverage text for skipped symlinks says that a link pointing inside the scanned folder was examined and "nothing was missed". That is not always true: the link's target can carry its own skip reason (vendored, too large, generated). The text overstates.
2. **Prototype-member lookup on untrusted input (fixed).** A language lookup indexes a plain object with an untrusted key, so `__proto__` or `constructor` returns a prototype member. It is not exploitable, because a vocabulary check refuses the value first. It is inconsistent with the `Object.hasOwn` pattern this repository uses elsewhere, and it is a pattern Sentinel itself would flag.

Other known limits: the command-line scan runs no hunter (above); nine of ten domains are not proven paths (above); no CVE or secret-entropy tooling; stacks without techniques (such as shell) are not examined; the CI self-scan asserts that the pipeline exits 0 and is not a finding gate.
