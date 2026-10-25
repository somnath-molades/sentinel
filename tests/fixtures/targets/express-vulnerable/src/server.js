// DELIBERATELY VULNERABLE fixture for Sentinel's test corpus. Never deploy.
// Each planted defect has a SAFE counterpart below it, so a true positive is
// distinguishable from a tool that flags every route and every query (spec 6.4).
const express = require('express')
const { Pool } = require('pg')
const app = express()
const db = new Pool()

// Negative control for the auth checks: a real middleware, so an authorized route
// is authorized by something a reader can point at.
function requireAuth(req, res, next) {
  if (!req.headers.authorization) return res.sendStatus(401)
  next()
}

// Planted: SQL built by string concatenation from user input.
app.get('/users', async (req, res) => {
  const rows = await db.query("SELECT * FROM users WHERE name = '" + req.query.name + "'")
  res.json(rows)
})

// Negative control: the same query, parameterized. Values are bound, not interpolated.
app.get('/users/search', async (req, res) => {
  const rows = await db.query('SELECT * FROM users WHERE name = $1', [req.query.name])
  res.json(rows)
})

// Planted: no authentication or authorization check on a destructive route.
app.delete('/users/:id', async (req, res) => {
  await db.query('DELETE FROM users WHERE id = ' + req.params.id)
  res.sendStatus(204)
})

// Negative control: the same destructive shape, behind an authorization check and
// parameterized. Nothing here should be reported.
app.delete('/sessions/:id', requireAuth, async (req, res) => {
  await db.query('DELETE FROM sessions WHERE id = $1', [req.params.id])
  res.sendStatus(204)
})

app.listen(3000)
