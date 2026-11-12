import { test, after, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { build } from 'esbuild'
import { unlink } from 'node:fs/promises'
import React from 'react'
import { create, act } from 'react-test-renderer'

const outfile = new URL('../.foreign-install-test.mjs', import.meta.url)
await build({ entryPoints: [new URL('../src/components/ForeignInstallDialog.tsx', import.meta.url).pathname],
  outfile: outfile.pathname, bundle: true, format: 'esm', platform: 'node',
  external: ['react', 'react/jsx-runtime'], plugins: [{ name: 'offline-api', setup(b) {
    b.onResolve({ filter: /api\/client$/ }, () => ({ path: 'api', namespace: 'fixture' }))
    b.onLoad({ filter: /.*/, namespace: 'fixture' }, () => ({ contents: 'export default {get: (...a)=>globalThis.fixtureAPI.get(...a), post: (...a)=>globalThis.fixtureAPI.post(...a)}' }))
  } }] })
const { ForeignInstallDialog, useForeignInstallAvailability } = await import(outfile.href)
after(() => unlink(outfile))
let tree, tick
const node = { id: 'foreign-node-1234', name: 'node-kh' }
const origin = 'https://kh.example.com:443'
const grant = () => ({ node_id: node.id, node_name: node.name, origin,
  control_url: origin+'/smite-node/'+'a'.repeat(32), installation_code: 'smi1_'+'a'.repeat(43),
  expires_at: Math.floor(Date.now()/1000)+7200 })
globalThis.window = { location: { origin: 'https://panel.example.com', protocol: 'https:' },
  setInterval: fn => { tick=fn; return 1 }, clearInterval: () => { tick=null } }
let clipboard
Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { clipboard: { writeText: async text => { clipboard=text } } } })
const originalNow=Date.now
afterEach(() => { if(tree) act(()=>tree.unmount()); tree=null; Date.now=originalNow; clipboard=undefined })
async function mount(existing=node) {
  await act(async()=> { tree=create(React.createElement(ForeignInstallDialog, { node:existing, onClose(){}, onReserved(){} })) })
  await act(async()=>tree.root.findByProps({'aria-label':'Foreign Gateway domain'}).props.onChange({target:{value:'kh.example.com'}}))
  if(!existing) await act(async()=>tree.root.findByProps({'aria-label':'Node name'}).props.onChange({target:{value:node.name}}))
}
async function submit() { await act(async()=>tree.root.findByType('form').props.onSubmit({preventDefault(){}})) }
const packet=()=>tree.root.findByProps({'aria-label':'One-time installation information'}).props.value
const button=text=>tree.root.findAllByType('button').find(b=>b.children.join('')===text)

test('reserve name/domain, issue 2-hour grant and copy exact packet',async()=>{
  const calls=[]
  globalThis.fixtureAPI={post:async(path,body)=>{calls.push([path,body]);return {data:path.endsWith('reserve')?{node_id:node.id,name:node.name,status:'pending'}:grant()}}}
  await mount(null);await submit()
  assert.equal(calls.length,2);assert.equal(calls[0][0],'/node-pairing/reserve')
  assert.equal(calls[1][1].ttl_seconds,7200)
  const data=JSON.parse(packet());assert.equal(data.panel_url,'https://panel.example.com');assert.equal(data.node_id,node.id)
  await act(async()=>button('Copy installation information').props.onClick())
  assert.equal(clipboard,packet())
})
test('issue failure retries same reservation without duplicate Node',async()=>{
  let reserves=0,issues=0
  globalThis.fixtureAPI={post:async path=>{
    if(path.endsWith('reserve')){reserves++;return {data:{node_id:node.id,name:node.name,status:'pending'}}}
    if(++issues===1)throw Error('fixture');return {data:grant()}
  }}
  await mount(null);await submit();await submit();assert.equal(reserves,1);assert.equal(issues,2);assert.ok(packet())
})
test('lost reservation reply blocks blind repeated reservation',async()=>{
  let calls=0;globalThis.fixtureAPI={post:async()=>{calls++;throw Error('fixture')}}
  await mount(null);await submit();await submit();assert.equal(calls,1)
  assert.match(tree.root.findByProps({role:'alert'}).children.join(''),/unknown/)
})
test('invalid domain never sends a request',async()=>{
  let calls=0;globalThis.fixtureAPI={post:async()=>{calls++}}
  await mount();await act(async()=>tree.root.findByProps({'aria-label':'Foreign Gateway domain'}).props.onChange({target:{value:'https://127.0.0.1'}}))
  await submit();assert.equal(calls,0)
})
test('wrong identity response never displays a code',async()=>{
  globalThis.fixtureAPI={post:async()=>({data:{...grant(),node_id:'other-node-1234'}})}
  await mount();await submit();assert.equal(tree.root.findAllByType('textarea').length,0)
})
test('expiry clears code and permits same-node reissue',async()=>{
  let calls=0;globalThis.fixtureAPI={post:async()=>{calls++;return {data:grant()}}}
  await mount();await submit();const expires=JSON.parse(packet()).expires_at
  Date.now=()=>expires*1000+1
  await act(async()=>tick());assert.equal(tree.root.findAllByType('textarea').length,0)
  await submit();assert.equal(calls,2);assert.ok(packet())
})
test('revoke clears displayed code only on success',async()=>{
  let fail=true
  globalThis.fixtureAPI={post:async path=>{if(path.endsWith('revoke')&&fail)throw Error('fixture');return {data:grant()}}}
  await mount();await submit();await act(async()=>button('Revoke unused code').props.onClick());assert.ok(packet())
  fail=false;await act(async()=>button('Revoke unused code').props.onClick());assert.equal(tree.root.findAllByType('textarea').length,0)
})
test('closing aborts in-flight request and does not revoke',async()=>{
  let resolve,signal,calls=0
  globalThis.fixtureAPI={post:(_p,_b,options)=>{calls++;signal=options.signal;return new Promise(r=>resolve=r)}}
  await mount();act(()=>tree.root.findByType('form').props.onSubmit({preventDefault(){}}))
  act(()=>tree.unmount());tree=null;assert.ok(signal.aborted)
  await act(async()=>resolve({data:grant()}));assert.equal(calls,1)
})
test('capability requires issuance, origin trust and correct protocol',async()=>{
  function Probe(){return React.createElement('span',null,String(useForeignInstallAvailability()))}
  for(const data of [{foreign_install_enabled:true,origin_trust_ready:false,protocol:'smi1'},
                    {foreign_install_enabled:true,origin_trust_ready:true,protocol:'smi1'}]){
    globalThis.fixtureAPI={get:async()=>({data})}
    await act(async()=>{tree=create(React.createElement(Probe))})
    assert.equal(tree.root.findByType('span').children[0],String(data.origin_trust_ready))
    act(()=>tree.unmount());tree=null
  }
})
