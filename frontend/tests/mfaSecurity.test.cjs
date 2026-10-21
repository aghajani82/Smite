const { test } = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')

const memory = new Map()
global.localStorage = {
  getItem: key => memory.get(key) ?? null,
  setItem: (key, value) => memory.set(key, value),
  removeItem: key => memory.delete(key),
}
global.window = { location: { pathname: '/settings', href: '/settings' } }

const { default: api } = require('./mfaClient.generated.cjs')
const response = api.interceptors.response.handlers[0].rejected

async function rejectStatus(url, status) {
  await assert.rejects(response({ config: { url }, response: { status } }))
}

test('wrong setup password or MFA confirmation does NOT invalidate a valid session', async () => {
  for (const url of [
    '/auth/2fa/setup', '/auth/2fa/enable', '/auth/2fa/disable',
    '/auth/login', '/auth/logout',
  ]) {
    memory.set('token', 'valid-session')
    memory.set('username', 'operator')
    global.window.location.href = '/settings'
    await rejectStatus(url, 401)
    assert.equal(memory.get('token'), 'valid-session', url)
    assert.equal(global.window.location.href, '/settings', url)
  }
})

test('rejected or expired bearer token still clears auth session', async () => {
  memory.set('token', 'expired')
  memory.set('username', 'operator')
  global.window.location.pathname = '/settings'
  global.window.location.href = '/settings'
  await rejectStatus('/auth/me', 401)
  assert.equal(memory.has('token'), false)
  assert.equal(memory.has('username'), false)
  assert.equal(global.window.location.href, '/login')
})

test('login and settings keep the user-requested simple authenticator sequence', () => {
  const source = path.resolve(__dirname, '../src')
  const login = fs.readFileSync(path.join(source, 'pages/Login.tsx'), 'utf8')
  const settings = fs.readFileSync(path.join(source, 'components/TwoFactorSettings.tsx'), 'utf8')
  assert.match(login, /id="mfa-code"/)
  assert.match(login, /required=\{mfaRequired\}/)
  assert.match(login, /mfa_code: mfaCode\.trim\(\) \|\| undefined/)
  assert.match(settings, /<img src=\{enrollment\.qr_data_uri\}/)
  assert.match(settings, /\/auth\/2fa\/setup/)
  assert.match(settings, /\/auth\/2fa\/enable/)
  assert.match(settings, /\/auth\/2fa\/disable/)
  assert.doesNotMatch(settings, /api\.qrserver\.com|chart\.googleapis\.com/)
})


test('operator sign-out is server-confirmed and warns on network failure', () => {
  const root = path.resolve(__dirname, '../src')
  const context = fs.readFileSync(path.join(root, 'contexts/AuthContext.tsx'), 'utf8')
  const layout = fs.readFileSync(path.join(root, 'components/Layout.tsx'), 'utf8')
  const settings = fs.readFileSync(path.join(root, 'components/TwoFactorSettings.tsx'), 'utf8')
  assert.match(context, /await api\.post\('\/auth\/logout'/)
  assert.match(context, /if \(error\?\.response\?\.status !== 401\)/)
  assert.match(context, /return false[\s\S]*clearLocalSession\(\)/)
  assert.match(layout, /const revoked = await logout\(\)/)
  assert.match(layout, /setLogoutFailed\(true\)/)
  assert.match(layout, /Sign out on all devices/)
  assert.match(settings, /localStorage\.removeItem\('token'\)/)
})
