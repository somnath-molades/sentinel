---
id: entrypoint-reachability-under-auth-state
vuln_classes: [reachability, broken-access-control]
cwe: [CWE-862, CWE-863]
depth_tier: L2
domain: authorization
stacks: [node, python, go, generic]
fix_patterns:
  - stack: generic
    tier: mechanical
    guidance: Add the missing authorization check to the route that reaches the vulnerable path, at the same layer the application's other routes use, so it is enforced consistently rather than in one handler's own style.
  - stack: generic
    tier: guided
    guidance: Where the route is registered before the middleware that would guard it, fix the registration order and add a test that asserts an unauthenticated request to that route is rejected — order bugs reappear when routes are moved.
  - stack: generic
    tier: design-change
    guidance: Make authorization deny-by-default — require every route to declare its required authority at registration and refuse to start when one does not, so a new route cannot be unprotected by omission.
references:
  - https://cwe.mitre.org/data/definitions/862.html
  - https://owasp.org/Top10/A01_2021-Broken_Access_Control/
  - https://github.com/anthropics/defending-code-reference-harness
provenance:
  pack: defending-code
  upstream_commit: d3bea6b5793b5f3d59a75ebe69a58efa88383145
---

## Detection

A vulnerable code path is callable from a real entry point, and the authentication state required to get there is weaker than the code's author assumed. Establish the entry-point inventory first — HTTP routes, queue and event consumers, scheduled jobs, command-line subcommands, exported library functions — then work from each one toward the vulnerable function. The finding is the combination of an inbound call path and the authorization actually enforced along it.

## Verification

Determine the authorization state at the entry point by reading what is actually applied to that route, not what the surrounding routes do. Check middleware registration order, because a route registered before a guard is not covered by it; check for guards applied per-router rather than globally, where a second router mounted elsewhere misses them; and check whether the guard authenticates only, when the operation also needs an ownership or role check. Then confirm the call path from entry point to the vulnerable function actually exists, naming each hop. Where an entry point is reached only by another internal component, state that and say which, because an internally-reachable path with a tainted caller is still reachable — just one step further out.

## Defensive use

Proves whether a finding is exploitable or merely present: the same vulnerable function is an unauthenticated remote issue, an authenticated-user privilege escalation, or unreachable dead code, and only the reachability and auth-state analysis distinguishes them. This is what stops a scanner's output from being triaged by guesswork. Verify it statically by enumerating entry points, reading the authorization actually applied to the one in question — including middleware registration order and whether the check covers authorization and not just authentication — and naming each hop from entry point to the vulnerable function. The fix is to add the missing check at the layer the rest of the application uses, correct any ordering that bypasses it, and make route authorization deny-by-default so the next unprotected route fails to start rather than shipping.
