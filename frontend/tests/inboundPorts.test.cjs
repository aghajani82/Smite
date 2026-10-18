const { test } = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const { parseInboundPorts } = require('./inboundPorts.generated.cjs')

test('inbound port is explicitly chosen, never silently defaulted', () => {
  assert.equal(parseInboundPorts(''), null)
  assert.equal(parseInboundPorts(' '), null)
  assert.deepEqual(parseInboundPorts('56053'), [56053])
  assert.deepEqual(parseInboundPorts('56053, 8081'), [56053, 8081])
  assert.deepEqual(parseInboundPorts('1,65535'), [1, 65535])
})

test('invalid, duplicated and accidentally pasted commands are rejected', () => {
  for (const bad of [
    '0', '65536', '56053abc', '56053;whoami', '56053,,8081',
    '56053,', '56053,56053', '1.5', '-1', 'NaN', '8080\n8081',
    '0x1f90', '1e3', '999999999999999999999999999',
  ]) {
    assert.equal(parseInboundPorts(bad), null, bad)
  }
})

test('default UI stays small, preserves user-entered values and requires both nodes', () => {
  const root = path.resolve(__dirname, '..', 'src')
  const form = fs.readFileSync(path.join(root, 'pages/Tunnels.tsx'), 'utf8')
  const page = form.split('const AddTunnelModal =', 2)[1].split('const BACKHAUL_TRANSPORTS:', 1)[0]
  assert.match(page, /core: 'frp'/)
  assert.match(page, /ports: ''/)
  assert.match(page, /backhaulState\.public_port/)
  assert.match(page, /parseInboundPorts\(portInput\)/)
  assert.match(page, /!formData\.iran_node_id \|\| !formData\.foreign_node_id/)
  assert.match(page, /aria-expanded=\{showTechnicalSettings\}/)
  assert.match(page, /disabled=\{creating \|\| nodes\.length === 0 \|\| servers\.length === 0\}/)
  assert.doesNotMatch(page, /console\.log\('Backhaul tunnel creation/)
  assert.doesNotMatch(page, /formData\.ports \|\| '8080'/)
  const sidebar = fs.readFileSync(path.join(root, 'components/Layout.tsx'), 'utf8')
  assert.match(sidebar, /aria-controls="smite-extra-tools"/)
  assert.match(sidebar, /setShowMoreTools\(true\)/)
  const dashboard = fs.readFileSync(path.join(root, 'pages/Dashboard.tsx'), 'utf8')
  assert.match(dashboard, /role="alert"/)
  assert.match(dashboard, /setError\(true\)/)
  assert.match(dashboard, /statusUnknown/)
})
