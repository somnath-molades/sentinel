---
id: sql-injection-built-query-string
vuln_classes: [sql-injection]
cwe: [CWE-89]
depth_tier: L1
stacks: [node, python, php, go]
fix_patterns:
  - stack: node
    tier: mechanical
    guidance: Pass the statement with placeholders and the values as a separate array argument, so the driver binds them instead of the string being assembled first.
  - stack: python
    tier: mechanical
    guidance: Give the cursor the statement with parameter markers and a values tuple as the second argument; never pre-format the statement with the values.
  - stack: generic
    tier: guided
    guidance: Identifiers — table and column names, sort direction — cannot be bound as parameters. Map the caller's value through a fixed allowlist to a constant you wrote, and reject anything outside it.
references:
  - https://cwe.mitre.org/data/definitions/89.html
  - https://owasp.org/www-community/attacks/SQL_Injection
  - https://github.com/tanviet12/vbsec
provenance:
  pack: vbsec
  upstream_commit: 1b86c27936d350d1a9ca67f044341262d4219d4e
---

## Detection

A SQL statement is assembled as a string with a variable spliced into it — by concatenation, template literal, format call or percent interpolation — and the finished string is handed to a database execute or query call. The telling detail is argument shape: one string argument where the driver also offers a statement-plus-values form.

Named sinks to search for, each where the first argument is an assembled string rather than a statement with placeholders:

- node: `connection.query`, `pool.query`, `client.query`, `db.run`, `db.all`, `db.get`, `sequelize.query`, `knex.raw`, `prisma.$queryRawUnsafe`, `prisma.$executeRawUnsafe`, `entityManager.query`
- python: `cursor.execute`, `cursor.executemany`, `connection.execute`, `Model.objects.raw`, `Model.objects.extra`, `sqlalchemy.text`, `session.execute`
- php: `mysqli_query`, `mysqli::query`, `PDO::query`, `PDO::exec`, `pg_query`, and `DB::select` / `DB::statement` / `whereRaw` / `selectRaw` in Laravel
- go: `db.Query`, `db.QueryRow`, `db.Exec`, `tx.Query`, `tx.Exec`, and `gorm`'s `Raw` and `Exec`

The paired safe forms worth recognising so they are not flagged: a second argument carrying the values (`query(sql, values)`, `execute(sql, params)`), placeholder markers `?`, `$1`, `%s` or `:name` inside the statement, and Prisma's `$queryRaw` tagged-template form, which parameterises its interpolations.

## Verification

Read the function containing the call and determine where the interpolated variable comes from. Trace it back to a request parameter, body field, header, or an earlier database read whose value originated from a user. If it resolves to a constant, an enumeration member or a value already validated against a fixed set, the construct is ugly but not exploitable — say which. Also confirm nothing binds the value on the way: a parameter marker present elsewhere in the same statement does not protect the interpolated fragment.

## Defensive use

Proves that a caller can change the structure of a query the application runs, not merely its inputs — which in practice means reading tables the endpoint never intended to expose, and on many engines writing or reading files through the database's own functions. Verify it statically by reading backwards from the interpolation to its origin and confirming an untrusted value reaches the statement text unbound. The fix is to pass placeholders plus a values argument so the driver binds every value; for identifiers, which cannot be bound, map the input through an allowlist to a literal you control.
