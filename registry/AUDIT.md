# Upstream license audit

Audit date: 2026-10-25. Auditor: project owner's agent, Task 5.

Every license below was determined by fetching and reading the repository's own
`LICENSE` file through the GitHub contents API (`gh api repos/<o>/<r>/contents/LICENSE`)
and reading the licence text itself. GitHub's sidebar label and README badges were
not used as evidence; where GitHub's own detector disagreed with the file, the file
wins and the disagreement is noted.

Ingestion modes follow spec §5.3:

- `vendored` — permissive licence (MIT / Apache-2.0 / BSD). Content may be copied,
  with attribution in `NOTICE` and the upstream commit pinned.
- `original` — licence `UNSTATED` (no `LICENSE` file, or ambiguous terms). All rights
  reserved. Nothing is copied; a Sentinel-authored entry may cover the same public
  vulnerability class, citing the repository as inspiration only.
- `external` — copyleft or otherwise restrictive. Kept out of tree entirely; fetched
  on user request at install time.

## Audit table

| # | Source (as named by owner) | Repository | Licence as read | Read from | Commit audited | Coverage areas | Ingestion mode |
|---|---|---|---|---|---|---|---|
| 1 | Claude Cybersecurity — Agrici Daniel | https://github.com/AgriciDaniel/pya | MIT | `LICENSE` (`MIT License` / `Copyright (c) 2026 AgriciDaniel`) | `416c17fa09a234a1a34709d31b335d30196b9899` | Security-audit plugin, 9 specialist agents, dated threat feed | `vendored` (not used in this task) |
| 2 | VBsec — Tanviet12 | https://github.com/tanviet12/vbsec | MIT | `LICENSE` (`MIT License` / `Copyright (c) 2026 Bùi Tấn Việt`) | `1b86c27936d350d1a9ca67f044341262d4219d4e` | 22 vulnerability rule files: secrets, injection, XSS, IDOR, access control, crypto, dependencies | `vendored` — **normalized as pack `vbsec`** |
| 3 | OS skills — Agna | **NOT LOCATED** | — | — | — | — | unassigned |
| 4 | Coast Security (as a skill) | **NOT LOCATED** | — | — | — | — | unassigned |
| 5 | Agent Guard — Go Plus Security | https://github.com/GoPlusSecurity/agentguard | MIT | `LICENSE` (`MIT License` / `Copyright (c) 2025 GoPlusSecurity`) | `337b767ea42eab3c51df7e6a777e9432d8effd94` | Agent-runtime guard: malicious skill detection, secret exfiltration, 24 detection rules, trust registry | `vendored` (not used in this task) |
| 6 | Bug Hunter — Codex Star69 | https://github.com/codexstar69/bug-hunter | MIT | `LICENSE` (`MIT License` / `Copyright (c) 2026 codexstar69`) | `3be69733a27aa04d4f5620df203c05350d162067` | Adversarial bug hunting with auto-fix, multi-agent | `vendored` (not used in this task) |
| 7 | CC Safety Net — Kenryu42 | https://github.com/kenryu42/cc-safety-net | MIT | `LICENSE` (`MIT License` / `Copyright (c) 2026 J Liew`) | `71baf747e2a5246bdf613a2894f2d6e7a5ad80bf` | Pre-execution guard: destructive git/filesystem commands, sensitive-file access | `vendored` (not used in this task) |
| 8 | Defending Code — Anthropic | https://github.com/anthropics/defending-code-reference-harness | Apache-2.0 | `LICENSE` (full Apache 2.0 text; appendix completed with `Copyright 2026 Anthropic PBC`) | `d3bea6b5793b5f3d59a75ebe69a58efa88383145` | Threat modelling, static vuln scan, triage/exploitability, patching, ASAN-verified autonomous scanner | `vendored` — **normalized as pack `defending-code`** |
| 9 | Trail of Bits skills — Trail of Bits | https://github.com/trailofbits/skills | CC-BY-SA-4.0 | `LICENSE` (`Attribution-ShareAlike 4.0 International`) | `196a9073ab10d35bacf111f945e02c00b2c6883a` | Security research, vulnerability detection, audit workflows | `external` — ShareAlike is copyleft; keep out of tree |
| 10 | Security audit — Cloudflare | https://github.com/cloudflare/security-audit-skill | MIT | `LICENSE` (`MIT License` / `Copyright (c) 2025-2026 Cloudflare, Inc.`) | `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` | Multi-phase security audit with independently verified findings | `vendored` (not used in this task) |
| 11 | Claude Red | https://github.com/SnailSploit/Claude-Red | MIT | `LICENSE` (`MIT License` / `Copyright (c) 2024-2025 SnailSploit / Kai Aizen`) | `a8de813edc9f66f60d44cfe42d47750e89d9930b` | Curated offensive-security skill library (red-team operator skills) | `vendored` (not used in this task) |

`vendored (not used in this task)` means: the licence permits vendoring and the mode is
recorded, but no content has been ingested yet. Only sources 2 and 8 were normalized.

### Notes on individual determinations

- **1 — Claude Cybersecurity.** The owner's name does not match any current repository
  name under `AgriciDaniel`. Identification is not a guess: `GET /repos/AgriciDaniel/claude-cybersecurity`
  returns a GitHub rename redirect to `AgriciDaniel/pya`, so `pya` is that repository
  under its new name. Recorded under the canonical name with the old name as evidence.
- **3 — OS skills (Agna).** Not located. Searched: GitHub user search for `agna` and
  `fullname:agna` (the only exact login `agna` owns a single repository, `agna/Test`,
  empty description, unrelated); repository search for `os-skills in:name` (389 results,
  none owned by any account resembling "Agna"); `os-skills claude`. Several plausible
  look-alikes exist (`ArtemXTech/personal-os-skills`, `ncklrs/startup-os-skills`,
  `BayramAnnakov/ai-personal-os-skills`). None is attributable to "Agna" and none was
  substituted. Owner input needed: a URL.
- **4 — Coast Security.** Not located. Searched: `coast security skill`, `coast claude code`,
  `coast-security`, `COAST framework security agent`, and GitHub user search for
  `coast security`. Results are physical-security companies and unrelated projects.
  No Claude/agent skill named "Coast Security" was found. Owner input needed: a URL.
  If "COAST" is an acronym for a framework rather than a vendor name, that expansion
  would make the search tractable.
- **8 — Defending Code.** GitHub's licence detector reports `NOASSERTION` for this
  repository. Reading the file shows why: it is the complete, unmodified Apache
  License 2.0 text whose closing appendix has been filled in with
  `Copyright 2026 Anthropic PBC` instead of being left as the bracketed template.
  The operative terms are verbatim Apache-2.0, so the licence is Apache-2.0 and the
  detector label is a false negative. This is exactly the case where a sidebar label
  would have produced the wrong answer — in the conservative direction here, but
  wrong either way.
- **9 — Trail of Bits skills.** CC-BY-SA-4.0's ShareAlike condition would require
  derivative registry entries to be licensed under CC-BY-SA, which conflicts with
  Sentinel's MIT licence. Assigned `external`; it is not vendored and no entry is
  derived from it. It is also not used as an `original`-mode inspiration source,
  because reading it to write "our own" version of the same material is the kind of
  derivation the ShareAlike term is about.
- **No source was recorded as `UNSTATED`.** Every located repository has a real
  `LICENSE` file. The `original` mode is therefore unexercised by this audit; the two
  packs are both `vendored`.

## Packs normalized in this task

**What was and was not copied.** Both packs are `ingestion_mode: vendored`, which
records a licensing determination: these licences permit copying, and `NOTICE`
attributes them. It does not describe what happened. **No upstream text is reproduced
in either pack.** Every `detection`, `verification`, `defensive_use` and
`fix_patterns[].guidance` string was written for this registry. `upstream_commit`, in
both `pack.yaml` files and in each entry's `provenance`, therefore pins *the commit
that was read and audited* and against which the subject-matter mapping was made — not
a commit text was taken from. `NOTICE` records this per pack as `Derivation: inspired`
and `Modified: no`. The schema has no field for the distinction and none was invented;
see requirement 27.

Chosen for dissimilarity, as the brief requires. Both characterisations below were
re-verified against the pinned commit's git tree after a review challenged the
original wording; the correction is noted where it applies.

- **`vbsec`** (source 2) — *content decomposed per vulnerability class*. Knowledge
  lives in hand-written markdown rule files, each with a tiny frontmatter block
  (`id`, `severity_max`, `applies_to`) and prose sections. Prose is Vietnamese.
  The layout is wider than first recorded: the skill is shipped three times, once
  per target agent, as `skills/vbs-scan-security/`, `skills/antigravity/vbs-scan-security/`
  and `skills/codex/vbs-scan-security/`. Each copy carries the same 22 generic rules
  under `rules/generic/` — 66 generic rule files in the tree for 22 distinct rules —
  plus per-language overlay files under `rules/languages/{dotnet,go,php,python,typescript}/`
  that refine a subset of those rules. The nine entries in this pack map to nine of
  the 22 generic rules. (The original audit named only
  `skills/vbs-scan-security/rules/generic/`, which does exist at the pinned commit
  and is the copy that was read, but presenting it as the whole layout understated
  the duplication. See requirement 25.)
- **`defending-code`** (source 8) — *content decomposed per pipeline phase*. A Python
  package (`pyproject.toml`, `harness/`, `bin/`, `dnr_harness/`) implementing a
  scanning, triage and patching pipeline, **and** — this was missing from the original
  audit — a skill tree at `.claude/skills/` with one directory per phase
  (`threat-model`, `vuln-scan`, `triage`, `patch`, `verify`, `dnr-hunt`,
  `dnr-respond`, `customize`, `quickstart`), each holding a `SKILL.md` and sometimes
  a `README.md` and supporting documents, plus thirteen operator documents under
  `docs/`. So it is not "a tool with no markdown"; it is a hybrid.
  What remains true is the decomposition: no file corresponds to a vulnerability
  class. A vulnerability-class taxonomy does exist, but as a flat inline list inside
  one prompt block of `.claude/skills/vuln-scan/SKILL.md`, grouped by triage value
  (memory safety, injection and code execution, auth/crypto/data) and accompanied by
  an explicit do-not-report list of known false positives. Memory-safety and
  reachability oriented; its unit of knowledge is a *workflow phase*, with classes as
  an inline checklist inside one of them.

**Honest assessment of the dissimilarity.** The pair is less dissimilar than the
original framing claimed. Both repositories ship agent skills as markdown, so the
"markdown repository versus code repository" contrast was wrong. The contrast that
does hold, and the one that actually taught something, is *how knowledge is
decomposed*: `vbsec` has one file per vulnerability class and nothing above L1, while
`defending-code` has deep dataflow and reachability reasoning organised by pipeline
phase with classes reduced to an inline list. That is a real and useful difference —
it is why extracting entries from `vbsec` was close to a mapping and extracting them
from `defending-code` was an interpretation — but it is a narrower difference than
"skill-shaped versus tool-shaped", and a future pack choice should be made on the
decomposition axis rather than on whether the repository contains code.

## Normalizer requirements

Friction points hit while normalizing these two packs by hand. This section is the
requirements input for the Phase 3 `ingest-pack` automation. Each item is something a
tool must do, must ask about, or must refuse to do.

### Identification and licensing

1. **Source names are not repository names.** Three of eleven sources needed search to
   locate and one (`Claude Cybersecurity` → `AgriciDaniel/pya`) was only resolvable via
   GitHub's rename redirect. The normalizer must take a URL as input, never a name. If
   given a name it must present candidates for human selection and refuse to pick.
2. **A rename redirect is evidence; a name similarity is not.** `GET /repos/<owner>/<old-name>`
   returning a 301 to another repository is a usable identification. Fuzzy name
   matching must be an explicit human confirmation step.
3. **GitHub's licence label cannot be trusted in either direction.**
   `defending-code-reference-harness` is labelled `NOASSERTION` and is plain
   Apache-2.0. The normalizer must fetch and parse the licence *file*, and must flag
   any disagreement between its own reading and the API label for human review rather
   than resolving it silently.
4. **Licence file location varies.** All eleven used a bare `LICENSE`, but
   `LICENSE.md`, `LICENSE.txt`, `COPYING` and per-subdirectory licences all occur in
   the wild. A monorepo of skills may licence subdirectories differently; the
   normalizer must check for a licence file inside the specific subtree it ingests,
   not only at the repository root.
5. **"Permissive" needs a closed allowlist, not a heuristic.** Assign `vendored` only
   on an exact match against a hard-coded list of licence texts/SPDX IDs
   (MIT, Apache-2.0, BSD-2/3-Clause, ISC). Anything else — including CC-BY, CC0, or
   an MIT text with an added clause — must route to human review. CC-BY-SA-4.0 must be
   `external`, and the normalizer must know that `external` means *do not read it for
   inspiration either*.
6. **Commit pinning must be explicit.** `GET /repos/<o>/<r>/commits` returns the
   default branch's HEAD, which is not necessarily what a `git clone` of a non-default
   branch gives, and is not stable between the audit and the ingest. The normalizer
   must resolve the SHA once and reuse that exact SHA for fetch, NOTICE and
   `provenance.upstream_commit`.
7. **Copyright holder differs from the GitHub account.** `tanviet12` → `Bùi Tấn Việt`,
   `kenryu42` → `J Liew`, `SnailSploit` → `SnailSploit / Kai Aizen`. Attribution must
   use the name in the licence file, not the account handle. Non-ASCII names must
   survive into `NOTICE` intact.

### Mapping upstream content onto the schema

8. **Upstream depth/severity vocabularies collide with ours.** `vbsec` uses `L1`–`L4`
   for *data-flow trust levels* (L1 = direct user input, L3 = hardcoded constant),
   the exact opposite axis from Sentinel's `L0`–`L5` *analysis depth tiers*. A
   normalizer that pattern-matches `L1` out of upstream text will assign depth tiers
   wrongly and confidently. Upstream tier vocabularies must be treated as foreign and
   never transcribed; `depth_tier` must be derived from what the detection *requires*
   (single-file grep = L0/L1, cross-file dataflow = L2) and that derivation needs a
   human confirmation step.
9. **`severity` has no home in our schema and must be dropped, not invented into one.**
   Every upstream rule carries a severity (`severity_max: CRITICAL`). `techniqueSchema`
   has no severity field and unknown keys are rejected. The normalizer must have an
   explicit drop-list of upstream fields, so the failure mode is "information lost on
   purpose" rather than "validation error at the end".
10. **`defensive_use` has no upstream source at all.** Neither repository contains
    anything shaped like it. Upstream prose is written for an operator running a scan,
    not for a reviewer deciding whether a finding is real. All thirteen `defensive_use`
    sections here were written from scratch, and each took longer than the rest of the
    entry combined. **The normalizer cannot generate this field; it must stop and
    require a human to write it.** Auto-generating it would turn the project's central
    control into boilerplate.
11. **`detection` / `verification` / `defensive_use` must be emitted as `##` body
    sections, never frontmatter.** Easy to get wrong when the natural intermediate
    representation is one flat object. The normalizer's writer must be section-aware
    and should round-trip its own output through `parseTechnique` before writing.
12. **One upstream file is not one technique entry.** `vbsec` has `20-outdated-dependency.md`
    and `22-vulnerable-dependency.md` covering one class from two angles; `03-xss.md`
    covers reflected, stored and DOM XSS with different detection methods and different
    depth tiers. Splitting and merging are judgment calls. The normalizer must propose
    a mapping and have it approved, not emit one file per file.
13. **Upstream decomposition may be by pipeline phase rather than by vulnerability
    class, and the class taxonomy may be buried inside a prompt.** *Corrected after
    review; the original wording of this item was wrong in a way that would have
    misled the normalizer.* `defending-code` is organised by phase — `.claude/skills/`
    has `threat-model`, `vuln-scan`, `triage`, `patch`, `verify` and more, each a
    `SKILL.md` — alongside `harness/*.py` and `docs/`. It is not true, as this item
    first claimed, that the knowledge is only in Python and prompts with no markdown
    and no class taxonomy to find: `.claude/skills/vuln-scan/SKILL.md` contains a flat
    class list (memory safety, injection and code execution, auth/crypto/data) inside
    the review-brief prompt block. What *is* true is that no **file** corresponds to a
    class, so there is no file-to-entry correspondence; the taxonomy must be extracted
    from inside a fenced prompt block in one file of one phase.
    The normalizer must therefore detect the decomposition axis explicitly — per-class
    files, or per-phase procedures with an inline taxonomy — and must not infer
    "no taxonomy present" from "no per-class files present". For the per-phase shape it
    may extract the inline class list as *candidate* entry subjects, but the entry
    bodies remain an interpretation of the workflow rather than a transformation of a
    source file, so it must still decline to auto-author and hand the candidates to a
    human.
    A corollary that was not visible before reading the prompt block: upstream encodes
    **negative** knowledge our schema cannot hold at all. `vuln-scan`'s brief carries
    an explicit do-not-report list of known false positives — volumetric denial of
    service, memory-safety findings in memory-safe languages outside unsafe blocks,
    XSS in a framework that escapes by default unless a raw-HTML escape hatch is used,
    findings in test files and build scripts, operator-controlled environment
    variables as an attack vector. `techniqueSchema` has no field for "do not report
    when", so that knowledge is dropped on ingest. The normalizer must report what it
    drops; whether the schema should gain a suppression field is a question for a later
    task, not something to invent during ingest.
14. **`fix_patterns[].stack` is an open string, so it will drift.** Nothing stops
    `node`, `nodejs`, `javascript` and `js` from all appearing. Upstream groups rules
    by language inconsistently (`applies_to: all`, plus per-language search-pattern
    sections inside one file). The normalizer needs a canonical stack vocabulary and a
    mapping table from upstream language labels; a later task should decide whether to
    close the enum.
15. **`fix_patterns[].tier` is absent upstream.** Whether a fix is `mechanical`,
    `guided` or `design-change` is a judgment about the codebase, not about the
    vulnerability. Upstream remediation text is a single prose blob. Requires a human
    call per fix pattern.
16. **CWE identifiers are mostly absent upstream and were looked up by hand.** `vbsec`
    rule files carry no CWE. Every CWE in these packs was supplied from public
    knowledge of the class. A normalizer can suggest from a class→CWE table but must
    mark suggestions as unverified.
17. **Upstream prose may not be in English.** `vbsec`'s rule bodies are Vietnamese.
    Even under a permissive licence that allows copying, the content is unusable
    verbatim in an English-only registry, so "vendored" did not mean "copy" here — it
    meant "permitted to copy, and we rewrote anyway". The normalizer must detect
    non-English upstream prose and route to human authoring; it must not machine
    translate security guidance and present the result as normalized upstream content.
18. **Upstream rule IDs are not usable as our IDs.** `SQL-INJECTION`, `01-hardcoded-secret`:
    uppercase, numerically prefixed, and not unique across packs. We need a slug
    convention (lowercase, hyphenated, class-plus-qualifier, unique registry-wide) and
    a collision check across all packs, which does not exist yet.

24. **Plain YAML frontmatter is a trap for prose-length values.** Three
    `fix_patterns[].guidance` strings here contained a colon followed by a space,
    which YAML reads as a nested mapping and rejects inside a compact sequence entry.
    The resulting error points at a column in the frontmatter, not at the sentence.
    A normalizer must serialize frontmatter with a real YAML emitter that quotes or
    block-folds as needed, never by string-templating the values into place.
25. **The same rule appears many times in one repository, and the normalizer must pick
    a canonical copy.** `vbsec` ships its skill once per target agent —
    `skills/vbs-scan-security/`, `skills/antigravity/vbs-scan-security/`,
    `skills/codex/vbs-scan-security/` — so its 22 generic rules appear as 66 files, and
    `rules/languages/{dotnet,go,php,python,typescript}/` adds per-language overlays
    that reuse the same rule numbers (`02-sql-injection.md` exists in six places). A
    normalizer that walks the tree for `*.md` and emits an entry per file would produce
    three to nine duplicates of every rule, each passing the schema and colliding on
    `id`. It must detect agent-variant directories (sibling directories with identical
    relative file sets), choose one canonical variant and record which, and treat a
    language overlay as *additional `stacks` and `fix_patterns` on the generic rule*
    rather than as a separate entry. The registry-wide `id` collision check (item 18)
    is what catches a failure here, so it is a prerequisite, not a nicety.
26. **Licence obligations must be materialised at ingest, not just referenced.** Both
    licences here require more than a copyright line once content is actually copied:
    MIT requires its permission notice to accompany substantial portions, and
    Apache-2.0 section 4 requires the licence text, retention of attribution notices,
    the contents of any upstream `NOTICE`, and a statement of changes. The normalizer
    must copy the upstream licence text into `registry/licenses/<pack>.txt`, copy any
    upstream `NOTICE` verbatim (neither of these two upstreams has one, which is itself
    a fact worth recording rather than leaving blank), and fill the `Modified` line
    from whether it altered what it copied. A pointer to a licence file that does not
    exist is worse than no pointer, so the ingest must fail if the file is missing.
27. **"Permitted to vendor" and "actually copied" are different facts and both must be
    recorded.** `packSchema.ingestion_mode` records the licence determination only. The
    `NOTICE` `Derivation:` line records what happened — `copied` or `inspired`. Keeping
    them separate matters because a later phase that treats `upstream_commit` as "the
    commit this text came from" would be wrong for an `inspired` pack, where the commit
    records what was *read and audited*, not what was reproduced. The normalizer must
    set `Derivation` from its own behaviour, never default it.

### Content safety

19. **The no-remote-install guard is a live constraint on security content.** Writing
    about supply-chain and dependency findings naturally pulls toward quoting a
    fetch-piped-to-interpreter command as the example of what to detect.
    `pnpm check:no-remote-install` fails the build on that pattern, in our own files,
    correctly. Every such pattern here is described in prose instead. The normalizer
    must run this guard on generated content *before* writing files, and must have a
    prose-only rule for describing execution patterns — upstream files often contain
    literal examples that cannot be copied through.
20. **Offensive-framed upstreams need reframing, not filtering.** `Claude-Red` is an
    offensive-security library; a keyword filter would reject it wholesale or admit it
    wholesale. The `defensive_use` requirement is what makes such material safe, and
    it is human-written (see 10) — so an offensive upstream implies a mandatory human
    authoring step, not an automated transform.

### Process

21. **Audit before ingest, as separate artefacts.** The audit determines what ingestion
    is permitted. The normalizer must read a committed audit row for the source
    (with a matching commit SHA) and refuse to ingest a source that has no audit row,
    or whose audit row pins a different commit.
22. **`NOTICE` needs machine-appendable structure.** It was prose with no per-entry
    template before this task. The format is now fixed by the commented example block
    at the top of the vendored section; the normalizer appends one block per vendored
    pack in that shape and must be idempotent — re-ingesting the same pack at the same
    commit must not duplicate the entry.
23. **Validation must be a gate, not a final step.** Working forward from upstream and
    validating at the end produced iterations on strict-schema errors (unknown keys,
    misplaced prose fields). The normalizer should validate each entry as it is
    produced and surface the error against the upstream file it came from.
