---
id: unknown-domain
vuln_classes: [sql-injection]
cwe: [CWE-89]
depth_tier: L1
domain: web-security
stacks: [node, python]
fix_patterns:
  - stack: node
    tier: mechanical
    guidance: Replace string-built queries with parameterized queries (placeholders plus a values array).
  - stack: python
    tier: guided
    guidance: Migrate raw SQL string building to the ORM query API so values are bound, not interpolated.
references:
  - https://owasp.org/www-community/attacks/SQL_Injection
provenance:
  pack: example-pack
---

## Detection

Look for SQL statements built by concatenating or interpolating variables into a query string passed to a database call.

## Verification

Read the code path from the request handler to the query call and confirm that user-controlled input reaches the string without being bound as a parameter.

## Defensive use

Proves that attacker-controlled input can change the structure of a database query in code you own. The fix is to bind values as parameters so input is always treated as data.
