// UI-only browser regression for the approved 90% desktop density.
// All backend API responses are deterministic fixtures; no live host is contacted.
const {chromium}=require(process.env.PLAYWRIGHT_MODULE || 'playwright')
const assert=require('node:assert/strict')
const fs=require('node:fs')

const near=(actual,expected,tolerance=1)=>Math.abs(actual-expected)<=tolerance
const apiFixtures={
  '/api/status/version':{version:'2.0.0-rc.7'},
  '/api/auth/me':{username:'fixture-user'},
  '/api/status':{
    system:{cpu_percent:7,memory_percent:46,memory_total_gb:1.6,memory_used_gb:0.6},
    nodes:{total:2,active:2},tunnels:{total:3,active:3}
  },
  '/api/nodes':[{metadata:{role:'iran'}},{metadata:{role:'foreign'}}],
  '/api/logs':{logs:[]}
}

;(async()=>{
 const browser=await chromium.launch({headless:true,...(process.env.CHROMIUM_PATH?{executablePath:process.env.CHROMIUM_PATH,args:['--no-sandbox','--disable-gpu']}:{})})
 fs.mkdirSync('login-brand-evidence',{recursive:true})
 try {
  for(const [width,height] of [[1366,768],[1920,1080],[390,844]]) {
   for(const language of ['en','fa']) for(const dark of [true,false]) {
    const context=await browser.newContext({viewport:{width,height},deviceScaleFactor:1})
    try {
     await context.addInitScript(({language,dark})=>{
      localStorage.setItem('language',language)
      localStorage.setItem('darkMode',JSON.stringify(dark))
     },{language,dark})
     const p=await context.newPage()
     await p.route(/^https:\/\//,r=>r.abort())
     await p.route('**/api/**',r=>{
      const url=new URL(r.request().url())
      const fixture=apiFixtures[url.pathname]
      return fixture ? r.fulfill({json:fixture}) : r.fulfill({status:404,json:{detail:'Fixture route unavailable'}})
     })
     await p.goto('http://127.0.0.1:3100/login')
     await p.locator('.smite-login-card').waitFor()
     assert.equal(await p.locator('img,.smite-login-glow').count(),0)
     assert.equal(await p.locator('.smite-login-brand-title').innerText(),language==='fa'?'اسمیت':'Smite')
     assert.equal(await p.getByText('Tunnel Management Platform',{exact:true}).count(),0)
     assert.equal(await p.locator('#username,#password,#mfa-code').count(),3)
     const baseSize=await p.locator('html').evaluate(e=>parseFloat(getComputedStyle(e).fontSize))
     assert.ok(near(baseSize,width>=1024?14.4:16,0.05),`Unexpected root size ${baseSize}px at ${width}px`)
     const loginBox=await p.locator('.smite-login-card').boundingBox()
     if(width>=1024) assert.ok(near(loginBox.width,403.2),`Expected 90% of 448px login card, got ${loginBox.width}`)
     assert.ok(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1))
     await p.locator('button[title]').click()
     assert.equal(await p.locator('html').evaluate(e=>e.classList.contains('dark')),!dark)
     await p.locator('button[title]').click()
     if(width===1366 && language==='en' && dark)
      await p.screenshot({path:'login-brand-evidence/login-90-percent.png',fullPage:true})

     // Simulated authenticated state to verify the actual desktop dashboard
     // gutter and card gaps; no API request is sent to a real server.
     await p.evaluate(()=>{
      localStorage.setItem('token','browser-fixture-only')
      localStorage.setItem('username','fixture-user')
     })
     await p.goto('http://127.0.0.1:3100/dashboard')
     await p.locator('.smite-dashboard-heading').waitFor()
     await p.locator('.smite-metric').first().waitFor()
     assert.ok(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),
      `Horizontal page overflow at ${width}px, ${language}, dark=${dark}`)
     const sidebar=await p.locator('aside').boundingBox()
     const heading=await p.locator('.smite-dashboard-heading').boundingBox()
     const metrics=await p.locator('.smite-metric').all()
     if(width>=1024) {
      assert.ok(near(sidebar.width,216),`Sidebar must scale from 240px to 216px, got ${sidebar.width}`)
      const first=await metrics[0].boundingBox()
      const second=await metrics[1].boundingBox()
      const rowGap=first.y-(heading.y+heading.height)
      const metricGap=second.x-(first.x+first.width)
      assert.ok(rowGap>=0 && rowGap<=23,`Dashboard header/metric gap expanded: ${rowGap}px`)
      assert.ok(metricGap>=0 && metricGap<=15,`Metric columns are too far apart: ${metricGap}px`)
      if(width===1366){
       const gutter=heading.x-(sidebar.x+sidebar.width)
       assert.ok(gutter>=25 && gutter<=31,`Excess sidebar/dashboard gutter: ${gutter}px`)
      }
     }
     if(width===1366 && language==='en' && dark)
      await p.screenshot({path:'login-brand-evidence/dashboard-90-percent.png',fullPage:true})
    } finally {
     await context.close()
    }
   }
  }
 } finally {await browser.close()}
 console.log('PASS: 12 fixture-only Login + Dashboard combinations; desktop 90% and mobile 100%, no enlarged gutters, card gaps or horizontal overflow.')
})().catch(e=>{console.error(e);process.exit(1)})
