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
