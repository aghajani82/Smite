// Offline UI-only contract: existing data/controls, no simulated values or new APIs.
const test = require('node:test')
const assert = require('node:assert/strict')
const { readFileSync } = require('node:fs')
const { join } = require('node:path')

const src = join(__dirname, '..', 'src')
const login = readFileSync(join(src, 'pages', 'Login.tsx'), 'utf8')
const layout = readFileSync(join(src, 'components', 'Layout.tsx'), 'utf8')
const dashboard = readFileSync(join(src, 'pages', 'Dashboard.tsx'), 'utf8')

test('the chosen theme remains a front-end skin, not a new auth implementation', () => {
  assert.match(login, /smite-login-card/)
  assert.match(login, /await api\.post\('\/auth\/login'/)
  assert.match(login, /mfa_code: mfaCode\.trim\(\) \|\| undefined/)
  assert.match(login, /mfaRequired/)
  assert.match(layout, /const revoked = await logout\(\)/)
  assert.match(layout, /logoutFailed/)
})

test('existing operator routes and G approval implementation are untouched', () => {
  for (const route of ['/dashboard', '/nodes', '/servers', '/tunnels', '/core-health', '/logs', '/settings']) {
    assert.ok(layout.includes("'"+route+"'"), route)
  }
  assert.doesNotMatch(login+layout+dashboard, /passkey|webauthn|approval-origin/i)
})

test('metrics come only from established status and logs APIs, never preview values', () => {
  assert.match(dashboard, /api\.get<Status>\('\/status'\)/)
  assert.match(dashboard, /api\.get<RegisteredNode\[\]>\('\/nodes'\)/)
  assert.match(dashboard, /api\.get<\{ logs: LogEntry\[\] \}>\('\/logs\?limit=5'\)/)
  assert.match(dashboard, /status\.system\.cpu_percent/)
  assert.match(dashboard, /status\.system\.memory_percent/)
  assert.match(dashboard, /status\.nodes\.active/)
  assert.match(dashboard, /status\.tunnels\.active/)
  assert.match(dashboard, /error \? t\.dashboard\.apiUnavailable/)
  assert.match(dashboard, /smite-dashboard/)
  assert.doesNotMatch(dashboard, /\b(48\.6 GB|37%|62%|12 active)\b/)
  assert.doesNotMatch(dashboard, /\/api\/monitoring|\/api\/metrics|\/api\/activity/)
})
