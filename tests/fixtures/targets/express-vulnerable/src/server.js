// DELIBERATELY VULNERABLE fixture for Sentinel's test corpus. Never deploy.
// Which routes are defective and which are sound is recorded in the tests that
// consume this fixture, not here: real-agent runs read this file (spec 8.3), and
// an answer key in the source would make the hunt trivially easy.
const express = require('express')
const jwt = require('jsonwebtoken')
const { Pool } = require('pg')
const app = express()
const db = new Pool()

function requireAuth(req, res, next) {
  const bearer = /^Bearer (.+)$/.exec(req.headers.authorization || '')
  if (!bearer) return res.sendStatus(401)
  try {
    req.user = jwt.verify(bearer[1], process.env.JWT_SECRET)
  } catch {
    return res.sendStatus(401)
  }
  next()
}

app.get('/users', async (req, res) => {
  const rows = await db.query("SELECT * FROM users WHERE name = '" + req.query.name + "'")
  res.json(rows)
})

app.get('/users/search', requireAuth, async (req, res) => {
  const rows = await db.query('SELECT * FROM users WHERE name = $1', [req.query.name])
  res.json(rows)
})

app.delete('/users/:id', async (req, res) => {
  await db.query('DELETE FROM users WHERE id = ' + req.params.id)
  res.sendStatus(204)
})

app.delete('/sessions/:id', requireAuth, async (req, res) => {
  const owned = await db.query('SELECT 1 FROM sessions WHERE id = $1 AND user_id = $2', [req.params.id, req.user.sub])
  if (owned.rowCount === 0) return res.sendStatus(403)
  await db.query('DELETE FROM sessions WHERE id = $1', [req.params.id])
  res.sendStatus(204)
})

app.listen(3000)
