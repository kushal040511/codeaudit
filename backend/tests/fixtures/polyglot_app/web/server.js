// Intentionally vulnerable Express server used as a CodeAudit scan fixture.
// DO NOT DEPLOY. Every issue here is deliberate.
const express = require('express')
const { exec } = require('child_process')
const _ = require('lodash')

const app = express()
app.use(express.json())

const JWT_SECRET = 'super-secret-jwt-signing-key'

app.get('/run', (req, res) => {
  // Command injection
  exec('ls ' + req.query.dir, (err, stdout) => res.send(stdout))
})

app.post('/calc', (req, res) => {
  // Code injection
  res.json({ result: eval(req.body.expression) })
})

app.get('/hello', (req, res) => {
  // Reflected XSS
  res.send('<h1>Hello ' + req.query.name + '</h1>')
})

app.post('/merge', (req, res) => {
  // Prototype pollution with a vulnerable lodash
  res.json(_.merge({}, req.body))
})

app.listen(3000)
