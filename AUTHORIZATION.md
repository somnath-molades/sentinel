> This document is not legal advice and is pending review by qualified counsel.

# Authorization to scan

Sentinel reads source code and reports security problems in it. Before it scans anything, you are asked to confirm the following.

## What you are attesting

By accepting, you state that:

1. The target you are pointing Sentinel at is yours, or you are authorized to assess its security.
2. If you are acting for someone else (an employer, a client, a project), you have their permission to scan this code and to see the results.
3. You will not use Sentinel's output to attack systems you do not own or are not authorized to test.
4. You understand that you, not the Sentinel project, are responsible for having that authorization.

If any of this is not true, do not accept.

## What Sentinel does and does not do

- Sentinel is read-only. It reads source files, configuration, infrastructure-as-code, dependency manifests and CI configuration. It does not read your git history: the `.git` directory is skipped, and a GitHub target is cloned one commit deep.
- It does not run your application, probe it, or connect to the target application or its infrastructure.
- When the target is a GitHub repository, Sentinel does fetch the repository's contents over the network (through `gh`) in order to read them.
- The attestation is recorded locally with a timestamp, and is asked for again for each new target.

## What Sentinel will accept as a target

The scope limit is enforced by the code, not just by this document. Sentinel accepts only:

- a local filesystem path, or
- a GitHub repository that the authenticated `gh` user can already access.

Anything else is refused by the tool. That includes URLs of running applications, IP addresses and hostnames, and repositories your `gh` login cannot access.

This limit narrows what Sentinel will do. It does not prove you are authorized: a local path or a repository you can reach may still belong to someone else. Authorization remains your responsibility.

See `TERMS.md` for liability and `ACCEPTABLE-USE.md` for the use rules.
