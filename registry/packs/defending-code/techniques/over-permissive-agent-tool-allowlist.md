---
id: over-permissive-agent-tool-allowlist
vuln_classes: [insecure-configuration, excessive-privilege]
cwe: [CWE-732, CWE-250]
depth_tier: L0
stacks: [agent-config, ci, generic]
fix_patterns:
  - stack: agent-config
    tier: mechanical
    guidance: Replace an unconstrained shell permission with the specific commands the workflow actually runs, each narrowed to the subcommand or prefix it needs, and drop the ones nothing uses.
  - stack: ci
    tier: mechanical
    guidance: Set the workflow's token permissions to read-only at the top level and grant a narrower write scope on the one job that needs it, rather than inheriting a broad default.
  - stack: generic
    tier: guided
    guidance: Derive the needed set from what the code actually invokes, then remove everything else and run the workflow to find what breaks. A permission list written from intention rather than observation drifts wider over time.
references:
  - https://cwe.mitre.org/data/definitions/732.html
  - https://owasp.org/Top10/A01_2021-Broken_Access_Control/
  - https://github.com/anthropics/defending-code-reference-harness
provenance:
  pack: defending-code
  upstream_commit: d3bea6b5793b5f3d59a75ebe69a58efa88383145
---

## Detection

A committed configuration file grants an automated actor more authority than its task needs. In agent and skill configuration this is an unconstrained shell or write permission where the workflow only ever runs a handful of read-only commands. In continuous integration it is a job that inherits write-scoped credentials for every operation when it only reads the repository. Both are single-file, grep-visible findings: the declaration is the evidence.

Named files and settings to search for:

- agent configuration: `allowed-tools` in a skill's frontmatter, and `permissions.allow` in `.claude/settings.json` or `.claude/settings.local.json` — the over-broad values are a bare `Bash`, a wildcard `Bash(*)`, or `Bash(<cmd>:*)` for a command that writes, where the workflow only enumerates and reads
- GitHub Actions: an absent top-level `permissions:` block, so the repository or organization default applies; `permissions: write-all`; `contents: write`, `packages: write` or `id-token: write` granted at workflow level rather than on the one job that needs it; `pull_request_target` or `workflow_run` triggers combined with a checkout of untrusted code; `secrets: inherit` on a reusable-workflow call; and an action referenced by a mutable tag rather than a commit SHA
- container and runtime: `privileged: true`, `--cap-add`, a host path mounted read-write, and a service account bound to a cluster-wide admin role
- cloud policy documents: a statement with `"Action": "*"` or `"Resource": "*"`, or a wildcard on a service prefix

The comparison that decides the finding is the declared set against the invocations actually present in the same tree; a declaration is a filter on what is permitted, never a record of what is used.

## Verification

Read the declared permission set against the operations the code actually performs, in the same tree. An unconstrained shell permission beside a workflow whose steps are all enumeration and search is over-broad; the same permission beside steps that build and publish is not. Note explicitly that a permission list is a filter on what is allowed, not a statement of what is used — so the comparison has to be made against the invocations, and the absence of a declaration means the platform default applies, which must be looked up rather than assumed restrictive.

## Defensive use

Proves that any defect elsewhere in the pipeline — a prompt-injected instruction in a file being reviewed, a compromised dependency in a build step, a bug in a script — executes with the full authority this configuration grants, rather than being confined to what the task needed. It converts a would-be contained incident into a repository-wide one. Verify it statically by diffing the declared permissions against the operations the code actually performs and by resolving the platform default where a declaration is absent. The fix is to narrow each grant to the specific commands or scopes observed in use, and to make the broad grant the exception on a single step rather than the inherited default.
