// Offline regression: the live Smite shared FRPS child is immutable except name.
const test = require('node:test')
const assert = require('node:assert/strict')
const { readFileSync } = require('node:fs')
const { join } = require('node:path')
const { isSharedFrpsChild, sharedChildRenamePayload } = require('./frpSharedChildEdit.generated.cjs')

test('owner, unrelated tunnels, or malformed markers never become shared children', () => {
  assert.equal(isSharedFrpsChild('frp', { bind_port: 7000 }), false)
  assert.equal(isSharedFrpsChild('backhaul', { shared_frps_owner: 'owner-frps' }), false)
  assert.equal(isSharedFrpsChild('frp', { shared_frps_owner: '' }), false)
  assert.equal(isSharedFrpsChild('frp', { shared_frps_owner: 123 }), false)
  assert.equal(isSharedFrpsChild('frp', { shared_frps_owner: 'owner-frps' }), true)
})

test('rename payload cannot contain child spec, tokens, control or proxy ports', () => {
  const result = sharedChildRenamePayload('  new name  ')
  assert.deepEqual(result, { name: 'new name' })
  assert.deepEqual(Object.keys(result), ['name'])
  assert.throws(() => sharedChildRenamePayload(' \t '), /name required/)
})

test('live edit form uses name-only shortcut and hides owner controls for children', () => {
  const source = readFileSync(join(__dirname, '../src/pages/Tunnels.tsx'), 'utf8')
  assert.match(source, /if \(isSharedFrpsChild\) \{[\s\S]*?api\.put\([^\n]*sharedChildRenamePayload\(formData\.name\)\)/)
  assert.match(source, /tunnel\.core === 'frp' && \(isSharedFrpsChild \? \(/)
  assert.match(source, /Shared FRPS child — rename only/)
  assert.match(source, /frp_token: isSharedFrpsChild \? ''/)
  assert.match(source, /type="password"[\s\S]*?value=\{formData\.frp_token\}/)
})

test('XHTTP console approval requires explicit fresh manual publication and blocks ambiguous retries', () => {
  const source = readFileSync(join(__dirname, '../src/pages/Tunnels.tsx'), 'utf8')
  assert.match(source, /انتشار مسیر XHTTP/)
  assert.match(source, /راهنمای تأیید مسیر/)
  assert.match(source, /درخواست انتشار مسیر/)
  assert.match(source, /ROOT_GRANT_APPROVED/)
  assert.match(source, /ثبت نهایی مسیر \(پس از تأیید G\)/)
  assert.match(source, /routeApprovalRequired &&/)
  assert.match(source, /routeStatus !== 'HOLD \/ Requires Review'/)
  assert.match(source, /routeApprovalRequired \? 'ثبت نهایی مسیر/)
  assert.match(source, /error\.response\?\.data\?\.detail === 'ROOT_OPERATOR_GRANT_REQUIRED'/)
  // Rejected browser approval must not be reactivated by an environment setting.
  assert.doesNotMatch(source, /VITE_STAGE15_APPROVAL_ORIGIN|openIndependentRouteApproval|window\.open|Passkey/)
  assert.match(source, /routeStatus !== 'Published'/)
})

test('Verify shows signed FRPS listener success without claiming XHTTP or reapplying', () => {
  const source = readFileSync(join(__dirname, '../src/pages/Tunnels.tsx'), 'utf8')
  const start = source.indexOf('const verifySharedFrpProxy = async')
  const end = source.indexOf('const [routePicker', start)
  assert.ok(start !== -1 && end > start)
  const verifyHandler = source.slice(start, end)
  assert.match(verifyHandler, /response\.data\?\.status === 'active'/)
  assert.match(verifyHandler, /تأیید FRP موفق بود/)
  assert.match(verifyHandler, /VLESS\/XHTTP/)
  assert.match(verifyHandler, /هیچ Reapply یا ری‌استارتی انجام نشد/)
  assert.doesNotMatch(verifyHandler, /reapplyTunnel\(|reapply-all|\/tunnels\/apply/)
})
