# Phase 0-1: deferred findings

Findings that review raised during the Phase 0-1 build and that were deliberately not fixed in that phase. They were collected from the phase ledger, which was scratch material and is not kept. This is the only maintained copy.

Counts: **112 entries across 14 tasks: 2 must-fix before merge and 110 minors.** Earlier summaries said "roughly 90". The ledger's own per-task tallies differ from the entries below in several places; this document counts each distinct finding once. Two entries are already closed or partly closed and are marked.

Each entry says what is wrong, where, and why it was deferred. Where a finding was reviewer-rated Minor, the reason is "minor, triage at final review" unless stated.

## Must fix before merge

**M1. Task 11, skip-reason text: false completeness claim.** The coverage text for a skipped in-tree symlink ends with "and nothing was missed". That is false: the symlink's target can itself carry a skip reason (vendored, too large, generated, binary), and those are listed separately. Same defect class (overstated completeness) that this task was already corrected for twice. Suggested replacement: "...was examined at its real path (any files within it skipped for other reasons are listed separately)". Deferred only to avoid a third fix round for one clause.

**M2. Task 12, language lookup: prototype-member read on untrusted input.** The language-to-stack lookup moved into core is a plain object index. A language named `__proto__` or `constructor` returns a prototype member instead of `undefined`. Not exploitable: the handler's membership check against the stack vocabulary refuses it, though with a misleading message. It matters because the repository already uses the own-property guard (`Object.hasOwn`) for this pattern in the stack detector, and because Sentinel would flag the pattern in other code. Fix is one line: an own-property check or a `Map`.

## Task 1: workspace, guard, CI

- T1-1. `scripts/check-no-remote-install.sh` and its test are excluded from the scan by path, yet both are executed (CI runs the script, vitest runs the test). A fetch-pipe-interpreter line added to either is never scanned. Close it by building the test's bad samples by string concatenation, then dropping both exclusions.
- T1-2. Residual regex evasions in the guard: `curl u | /usr/bin/env sh` (path prefix comes after the wrapper group); a pipe at end of line with the interpreter on the next line (only backslash continuations are joined); `sudo -u root sh` (the option's argument breaks the wrapper match); `xargs sh`.
- T1-3. If `git ls-files` succeeds but returns zero files, the guard passes silently. A zero-files check would make it fail closed.
- T1-4. Filenames containing newlines are mishandled by the guard's read loop.
- T1-5. The smoke test asserts only the semver shape, so `SENTINEL_CORE_VERSION` can drift from `packages/core/package.json` unnoticed (the duplicated literal was mandated by the brief).
- T1-6. Nobody checked that `tsconfig.base.json` `rootDir`/`outDir` agree with `tsconfig.typecheck.json` including `scripts/`; the clean lint run is the only evidence.
- T1-7. The guard excludes `:!docs` and `:!.superpowers` wholesale, so a shell snippet under `docs/` is never scanned (intended, but a blind spot).

## Task 2: legal documents

- T2-1. `NOTICE` carried a "(none yet)" line Task 5 had to delete and no per-entry template, so appends might not be uniform. Task 5 added a template; check it stayed consistent.
- T2-2. `ACCEPTABLE-USE.md:40,44` ("will be rejected", "need explicit maintainer review") are process promises with no CODEOWNERS or review rule behind them.
- T2-3. `legal-docs.test.ts:21-25`: the `/refus/` and `/local (filesystem )?path/` regexes (brief-mandated) are weak enough to pass on an incidental mention, and no test checks that the TERMS misuse clause exists.
- T2-4. `SECURITY.md:61` still reads "or open a network connection to it", inconsistent with the clarified `AUTHORIZATION.md` wording ("it" refers to the scanned target in a report-scope item).

Not findings but launch blockers from this task: ten placeholders need a human before publication (LICENSE copyright holder; SECURITY.md contact email, acknowledgement time, assessment time, fix and disclosure policy, reporter credit, project status, supported versions; TERMS.md governing law and contact), plus counsel review of all documents (spec section 9.5).

## Task 3: technique and pack schema

- T3-1. `scripts/gen-schema.mjs:4` imports zod by a relative path into `packages/core/node_modules`, which a hoisted install would break. Durable fix: export a `techniqueJsonSchema()` helper from core.
- T3-2. `technique.ts:169` reports "missing YAML frontmatter" for `---\n---\n` (empty frontmatter). Misleading, does not throw.
- T3-3. Duplicate `##` sections resolve silently with the last one winning; untested.
- T3-4. A `## ` line inside a fenced code block is treated as a heading; untested.
- T3-5. A missing `defensive_use` error reads "expected string, received undefined" with no pointer to the `## Defensive use` section.
- T3-6. `packages/core/package.json` `engines` and `exports` blocks were reformatted: diff noise.
- T3-7. Nobody verifies the committed `technique.schema.json` matches a fresh `gen:schema` run. A CI drift check is worth adding.
- T3-8. `formatIssues` at `technique.ts:93` is declared after use (hoisted, benign).
- T3-9. The Part B error message hardcodes the offending key names (benign).
- T3-10. The schema generator has no test of its own.

## Task 4: scope lock

- T4-1. No existence check on the remote root.
- T4-2. Parse failures and temp-directory failures share one message; the clone `catch` also covers temp-directory creation failure and would misreport it as a fetch failure.
- T4-3. The temp directory is absent from the returned contract (the caller derives it by assumption; see also T13-1).
- T4-4. A filesystem root is accepted as a target.
- T4-5. The scheme regex misclassifies a local path whose first segment contains a colon.
- T4-6. Input is trimmed for the emptiness test but used untrimmed.
- T4-7. Double-slash URL forms refuse on segment count.
- T4-8. A renamed repository's message does not name the new slug.
- T4-9. The host-pinning test asserts the CLI arguments but not the child environment variable (acceptable: the URL argument is the load-bearing pin).
- T4-10. Unverified: whether a CI checkout preserves the committed symlink fixture (mode 120000). Also, on a checkout without symlink support the fixture materialises as a text file (see T7-9).

## Task 5: registry packs

- T5-1. `reflected-xss-unescaped-output` fix 2 advises storing the sanitized form, which is contested: stored sanitized data cannot benefit from later sanitizer fixes; output-time escaping is the usual guidance.
- T5-2. The same entry is tagged L1 but its verification often needs a cross-file sink-to-origin trace.
- T5-3. The CORS entry omits `Vary: Origin` and the `null` origin.
- T5-4. `AUDIT.md` item 24 is numbered out of order, between 18 and 19.
- T5-5. The `NOTICE` template lines are indented and hash-prefixed while the prose says lines beginning with a hash are comments; a later parsing phase will trip on it.
- T5-6. Tests cannot check `defensive_use` quality mechanically.
- T5-7. A test uses an `endsWith` path check that is POSIX-only; `basename` would be portable.
- T5-8. `AUDIT.md:49-50` says the firm rows' coverage is "as firm as the rest of the row", which overstates: both firm-labelled characterisations were corrected after review. Suggested: "firmer than the advisory rows, though both characterisations were corrected once after review".
- T5-9. `AUDIT.md:51-52` says the advisory paraphrase is drawn from "GitHub description and README framing", while the implementer's report says "description and selective reading". One is wrong; if no README was read, drop the claim.
- T5-10. `AUDIT.md:26` (row 2) says "22 vulnerability rule files" while the body and normalizer requirement 25 say 66 files for 22 distinct rules. Should read 22 rules (66 files across agent variants).
- T5-11. The cosmetic class-list wording correction in `AUDIT.md` was not verified against the upstream file by the round-2 re-reviewer (low risk; round 1 verified the underlying grouping).

## Task 6: target profile schema

- T6-1. `Hotspot.domains` uses a bare string where `SkipRecord.reason` uses a non-empty constraint, so an empty-string domain validates. Judged negligible (matches the brief).

(Two other Task 6 minors, `generated_at` validated only as non-empty and nested strictness unpinned by tests, were closed in Task 7.)

## Task 7: walker and profile

- T7-1. `Hotspot.domains` is a bare string array, so nothing structurally prevents prose; the convention of domain identifiers is not enforced.
- T7-2. The two added skip-reason values (`not-regular`, `unreadable`) are never validated through the schema in a real profile: the one profile test that produces them omits `safeParse`.
- T7-3. `express-vulnerable` has no authorized-route negative control, so the authorization-hotspot assertion would pass against a fully authorized app.
- T7-4. The `.env` prefix match over-triggers on `.env.example` and `.env.sample`, which are routinely and correctly committed.
- T7-5. The data-layer regex lacks a case-insensitive flag, so lowercase SQL (the majority of real code) does not match that branch.
- T7-6. **Partly closed in Task 15.** `detect-stack` matched manifests by basename anywhere in the tree, so a target's own test fixtures contributed frameworks to its profile. Task 15 skips manifests under `fixtures`/`__fixtures__` directories. Still open: other conventions (`test`, `spec`, `__tests__`, `e2e`, `examples`) are not skipped, and a real application kept in a directory literally named `fixtures` is under-reported. Proper fix is weighting manifests by depth and path convention.
- T7-7. The file-size cap is checked after the file is opened, so one file past the cap is read for nothing.
- T7-8. `ELOOP` is the only error code mapped to the symlink reason; BSD behaviour differs.
- T7-9. The committed escape symlink would materialise as a text file on a checkout without symlink support, flipping one assertion.
- T7-10. `detectStack` and `StackInfo` are not re-exported from the package index while the other two recon exports are.
- T7-11. After the single-open refactor, every file passing the prefix check is read in full up to the cap and decoded, including markdown, JSON and YAML with no language, manifest role or env name, whose text the consumer discards. Cheap improvement: read beyond the prefix only when a consumer exists and the file is a consumer type.
- T7-12. The buffer is allocated before prefix classification, so a binary or non-UTF-8 file under the cap allocates up to a megabyte and discards it.
- T7-13. Nothing tests the error-code-to-symlink mapping directly; the symlink tests all exercise the dirent path.
- T7-14. An `EIO` on close is now swallowed, so a file counts as included despite a failed descriptor close. Acceptable because the data was already read. The close-failure path ships without a test (cannot be induced portably).
- T7-15. The `onFile` callback is synchronous, so a throwing scan rejects the whole walk; mitigated only by the regexes being bounded.
- T7-16. Containment gaps that need write access to the target or an OS facility Node lacks: an intermediate directory swapped for a symlink in the window between `readdir` and `open` of one file (needs fd-relative traversal); hardlinks cannot be detected.
- T7-17. Directory depth is unbounded.

## Task 8: registry router

- T8-1. Depth-tier ordering in the router is an unrequested, unspecified and untested ranking choice, kept because it is deterministic and cheap.
- T8-2. The wall-clock build stamp makes every regeneration a diff; it could be omitted from the committed index.
- T8-3. The filesystem-order test only checks the output is sorted, not that the build is order-independent (the reversed-index router test covers the router half).
- T8-4. The no-filter assertion sits inside the per-entry loop and is recomputed thirteen times.
- T8-5. The generator script and its build chain are exercised only manually.
- T8-6. Tests import `@sentinel/core` from the built `dist`, so a bare `vitest` run without a prior build tests stale output. Worth a test-script change so the build is implied.
- T8-7. The Phase 0-1 plan document still describes `selectTechniques` as returning an array; it returns `{ techniques, match }`.

## Task 9: findings store

- T9-1. The 64-bit fingerprint digest is adequate by the reviewer's arithmetic (collision probability about 3e-10 at 10^5 findings) but unchecked; `add` could compare technique id and file on a hit at no cost.
- T9-2. `add` does not validate that `line` is a finite number nor that technique id and file are strings.
- T9-3. `recordVerdict` does not validate that `agent` and `reasoning` are strings, so a missing field stores as `undefined`.
- T9-4. `list` clones the whole store on every call (negligible at this scale).
- T9-5. `additional_locations` growth is bounded by distinct pairs, but reachability is free text, so a verbose agent could grow it.
- T9-6. The field-separator test was reasoned correct but never mutation-run with the separators removed.

## Task 10: severity

- T10-1. The nested ternary for band cutoffs is long; a cutoff table would be easier to audit.
- T10-2. The `decideExitCode` line in the store is over 120 characters after the rename and wants wrapping.
- T10-3. Several inline object literals in the severity tests omit spaces after colons, copied verbatim from the brief.

## Task 11: reporters

- T11-1. The flat reachability claim inside unverified finding blocks.
- T11-2. The SARIF URI helper is unexported and tested only on the happy path; no case for a drive-letter path or ascending segments.
- T11-3. The symlink count is a lower bound when a scan is truncated.
- T11-4. Critical and high both map to SARIF `error` with no `security-severity`, so the band distinction is invisible in a code-scanning dashboard.
- T11-5. A code-scanning consumer may render only the first location entry, and the locations array is uncapped.
- T11-6. Needs-review and candidate counts are absent from the SARIF coverage object.
- T11-7. A heading level is skipped under one section.
- T11-8. The truncation note is missing from the empty-findings sentence.
- T11-9. A redundant validator option in the SARIF test.
- T11-10. A bad line number is silently rewritten rather than reported.
- T11-11. An extra location in a different file would be mislabelled with the primary's path. Unreachable today because dedupe keys on file, but a trap for whoever changes the fingerprint.
- T11-12. The summary line gives the symlink conditional correctly but does not repeat the cannot-tell admission; it points to the Coverage section instead.
- T11-13. One string uses double quotes against the file's single-quote convention.

## Task 12: MCP server

- T12-1. Serialisation covers only the profiling handler, so technique selection and finding recording can still write session state that a concurrent profile reset would strand in a new session. Low: agents normally call tools sequentially.
- T12-2. The report handler can see a stale profile after its clone was deleted.
- T12-3. A close arriving while profiling is mid-resolve runs cleanup before the clone directory is assigned, so that clone leaks. Narrow and pre-existing.
- T12-4. The report handler retries the registry load on every call when the load threw (harmless).
- T12-5. The pure-reasoning warning renders twice.
- T12-6. Findings are silently discarded when a new profile replaces a non-empty store.
- T12-7. A type assertion exists only to satisfy an optional-severity spread.

## Task 13: CLI

- T13-1. The `realpath` call in the clone-delete guard can itself throw from the cleanup block and mask the real error (related to T4-3: core returning a cleanup handle is the better design).
- T13-2. `huntersAvailable` sits on the public exported dependency type and wants an internal marker, or derivation from a real hunter registry once hunters exist. Setting it would make a gate pass with nothing hunted; an operator cannot reach it from the binary.
- T13-3. An unmapped language blocks the `--fail-on` gate even when other stacks are covered: conservative and consistent with the honesty goal, but worth knowing.
- T13-4. The clone-deleted message prints before cleanup runs.
- T13-5. The temp-directory assertion diffs a shared directory and flakes under parallel test files.
- T13-6. The binary tests require a prior build that a bare test run does not perform.
- T13-7. The CLI re-parses pack manifests (domain logic in the wrong layer), with the parse outside its `catch`, so one malformed manifest aborts the whole listing.
- T13-8. The default registry path resolves only inside the monorepo while help text calls it bundled.
- T13-9. No cleanup on an interrupt during a clone.

## Task 14: consent and attestation

- T14-1. The server surfaces a corrupt-record error through its generic profiling catch, so the message is prefixed as a profiling failure. Still a tool error naming the file; wording only.
- T14-2. The scan command passes its working directory unresolved while `init` writes under a realpathed one; lookups match but the refusal message may print a different spelling.
- T14-3. The server's test helper auto-attests, so only the explicit raw-call tests exercise refusal.
- T14-4. The authorization document is resolved relative to the package location and a missing file throws (fail-closed).
- T14-5. The three init-only dependency seams grow the public dependency type.

## Recorded decisions and inputs for later phases (not counted above)

These are not deferred defects; they are decisions and obligations the phase recorded.

- **Merge by squash, not merge commit.** A 1 MB filler fixture was committed in `1efa51b` and deleted in `16a9c8d`. An ordinary merge would keep the blob in the default branch's history permanently.
- **Product question, unanswered:** any readable local directory is in scope, so `sentinel scan /` and `sentinel scan ~` run. Whether to refuse or warn and confirm for something that does not look like a project is a UX and safety judgment for the owner.
- **Schema:** add `derivation: copied | inspired` to the pack schema (with a refinement forbidding external plus copied) so attribution accuracy is testable; add a field for upstream "do not report" lists (Defending Code ships one, and false positives are what destroy a scanner's credibility).
- **Registry content:** 11 of 13 entries list stacks with no matching `fix_patterns[].stack` (`go` lacks its own pattern in 7, `java` in 1); every one falls back to a `generic` fix pattern. The `original` ingestion mode has never been exercised. Coverage columns in `AUDIT.md` for seven un-ingested sources are paraphrased from descriptions, not tree reads; two sources (OS skills by Agna, Coast Security) were not located.
- **Router:** the coverage signal reports stack coverage, not class coverage. Class matching is exact, so a `sql-injection` query never selects `cross-file-taint-source-to-sink` or `entrypoint-reachability-under-auth-state`. Callers must query cross-cutting classes alongside concrete ones until a class design exists.
- **Fingerprints:** whitespace-collapse normalization does not survive a real formatter (Prettier turns `query(a+b)` into `query(a + b)`). Token-level normalization is needed before finding persistence exists.
- **Severity:** the store has no severity field and no multi-verifier merge policy; "last wins" is really "last verdict that supplied factors wins". Needs a core field and an explicit policy.
- **Symlinks:** the walker skips every symlink and cannot tell in-tree from out-of-tree, by design (no `realpath` in the walker). If a later phase wants to distinguish them, `readlink` is the route and `realpath` is not. Separately, the scope lock refuses a symlinked project directory (fail closed); revisit.
- **Reporters:** report skeleton carries no standards references (CWE/OWASP) or attacker-impact text; the explainer agent is Phase 2 work, and the reports say so in the interim.
- **Consent:** the MCP server reads the consent record from its own working directory; the Phase 2 harness wrapper must pass the consent root explicitly (no environment override, deliberately). For GitHub targets the clone happens before the attestation check because the target must be resolved to be identified; the clone is deleted on refusal. Core returning a cleanup handle and an authorization callback in the scope lock are refactor candidates.- **Stack detection:** the fixtures-directory heuristic (T7-6) is a stopgap.
