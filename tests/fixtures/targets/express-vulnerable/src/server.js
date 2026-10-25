// DELIBERATELY VULNERABLE fixture for Sentinel's test corpus. Never deploy.
const express = require('express')
const { Pool } = require('pg')
const app = express()
const db = new Pool()

// Planted: SQL built by string concatenation from user input.
app.get('/users', async (req, res) => {
  const rows = await db.query("SELECT * FROM users WHERE name = '" + req.query.name + "'")
  res.json(rows)
})

// Planted: no authentication or authorization check on a destructive route.
app.delete('/users/:id', async (req, res) => {
  await db.query('DELETE FROM users WHERE id = ' + req.params.id)
  res.sendStatus(204)
})

app.listen(3000)
