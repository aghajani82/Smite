const { test } = require('node:test')
const assert = require('node:assert/strict')
const { validStatus, registeredRoles, setupCount } = require('./dashboardData.generated.cjs')
const valid = () => ({system:{cpu_percent:0,memory_percent:25,memory_total_gb:4,memory_used_gb:1},nodes:{total:1,active:0},tunnels:{total:0,active:0}})
test('zero is real data, missing, malformed and non-finite metrics are unknown', () => {
  assert.equal(validStatus(valid()), true)
  for (const value of [null, {}, {system:{}}, {...valid(),nodes:null}]) assert.equal(validStatus(value), false)
  for (const field of Object.keys(valid().system)) {
    for (const value of [undefined, null, '0', NaN, Infinity, -1]) {
      const data=valid(); data.system[field]=value; assert.equal(validStatus(data), false)
    }
  }
  const data=valid(); data.tunnels.active=1; assert.equal(validStatus(data),false)
})
test('absent node list and unknown roles do not assert an empty deployment', () => {
  for (const data of [null, {}, [null], [{}], [{metadata:{role:'other'}}]]) assert.equal(registeredRoles(data),null)
  assert.deepEqual(registeredRoles([]),{iran:false,foreign:false})
  assert.deepEqual(registeredRoles([{metadata:{role:'iran'}}]),{iran:true,foreign:false})
})
test('setup progress requires fresh status; initial Iran-only install needs no tunnel', () => {
  const roles={iran:true,foreign:false}
  assert.equal(setupCount(roles,valid(),false),1)
  assert.equal(setupCount(roles,valid(),true),null)
  assert.equal(setupCount(roles,null,false),null)
  assert.equal(setupCount(null,valid(),false),null)
})
