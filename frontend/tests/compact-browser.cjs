// Local/CI visual regression with intercepted fixture APIs; never contacts a VPS.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const output = process.env.SCREENSHOT_DIR || 'compact-evidence'
fs.mkdirSync(output, { recursive: true })
const base = process.env.UI_URL || 'http://127.0.0.1:3100'
const status = { system: { cpu_percent: 7, memory_percent: 24, memory_total_gb: 2, memory_used_gb: .48 }, nodes: { total: 0, active: 0 }, tunnels: { total: 0, active: 0 } }
;(async () => {
  const browser = await chromium.launch({ headless: true, ...(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH, args: ['--no-sandbox', '--disable-gpu'] } : {}) })
  const results = []
  for (const [width, height] of [[1366,768],[1920,1080],[390,844],[390,420]]) {
    for (const language of ['en','fa']) for (const dark of [true,false]) {
      const context = await browser.newContext({ viewport: { width, height }, deviceScaleFactor: 1 })
      await context.addInitScript(({language,dark}) => { localStorage.setItem('language',language); localStorage.setItem('darkMode',JSON.stringify(dark)) }, {language,dark})
      await context.route(/^https:\/\//, route => route.abort());
      const page = await context.newPage(); page.setDefaultTimeout(10000); console.log('CASE',width,height,language,dark)
      const errors=[]; page.on('pageerror', e=>{errors.push(e.message);console.error(e.message)})
      let loginState = 'mfa'
      let holdLogin = false, releaseLogin
      await page.route('**/api/**', async route => {
        const path = new URL(route.request().url()).pathname
        if (path.endsWith('/auth/login') && holdLogin) await new Promise(resolve => { releaseLogin = resolve })
        let json = {}, code = 200
        if(path.endsWith('/auth/login')) { code = loginState === 'mfa' ? 428 : loginState === 'error' ? 401 : 200; json = code === 200 ? {access_token:'visual-fixture',username:'UI preview'} : {detail:'Fixture: invalid credentials'} }
        else if(path.endsWith('/auth/me')) json={username:'UI preview'}
        else if(path.endsWith('/status/version')) json={version:'2.0.0-rc.7'}
        else if(path.endsWith('/status')) json=status
        else if(path.endsWith('/logs')) json={logs:[]}
        else if(['/nodes','/tunnels','/health','/reset-config'].some(p=>path.endsWith(p))) json=[]
        else if(path.endsWith('/settings')) { code=503; json={detail:'Isolated visual fixture'} }
        else { code=503; json={detail:'No live API in visual test'} }
        await route.fulfill({status:code,json})
      })
      await page.goto(base+'/login', {waitUntil:'domcontentloaded'}); void 0
      await page.locator('.smite-login-card').waitFor()
      await page.getByText('v2.0.0-rc.7',{exact:true}).waitFor()
      assert.equal(await page.locator('img, .smite-login-brand-title, .smite-login-glow').count(),0)
      async function geometry() {
        return page.evaluate(() => {
          const r=document.querySelector('.smite-login-card').getBoundingClientRect(), f=document.querySelector('.smite-login-footer').getBoundingClientRect()
          return {width:r.width,height:r.height,dx:r.x+r.width/2-innerWidth/2,dy:r.y+r.height/2-innerHeight/2,footerGap:f.top-r.bottom,scrollWidth:document.documentElement.scrollWidth,viewport:innerWidth,scrollHeight:document.documentElement.scrollHeight}
        })
      }
      let g=await geometry(); const initialLogin = {...g}
      assert.ok(Math.abs(g.dx)<1,JSON.stringify(g))
      if(height>=768) assert.ok(Math.abs(g.dy)<1,JSON.stringify(g))
      assert.ok(g.footerGap>=0 && g.scrollWidth<=width,JSON.stringify(g))
      if(width===1366) { await page.setViewportSize({width:1920,height:1080}); const resized=await geometry(); assert.ok(Math.abs(resized.dx)<1 && Math.abs(resized.dy)<1); await page.setViewportSize({width,height}) }
      if(width===1366 && language==='en' && dark) await page.screenshot({path:output+'/login-1366-100.png'})
      if(width===390 && height===844 && language==='fa' && dark) await page.screenshot({path:output+'/login-mobile-rtl.png'})
      await page.locator('#username').fill('visual-test')
      await page.locator('#password').fill('not-a-real-password')
      await page.locator('button[type=submit]').click()
      await page.waitForFunction(()=>document.querySelector('#mfa-code').required)
      await page.locator('#mfa-code').fill('123456')
      loginState='error'; await page.locator('button[type=submit]').click()
      await page.getByText('Fixture: invalid credentials',{exact:true}).waitFor()
      g=await geometry(); assert.ok(g.footerGap>=0 && g.scrollWidth<=width)
      if(height>=768) assert.ok(Math.abs(g.dy)<1)
      await page.locator('button[title]').click()
      assert.equal(await page.locator('html').evaluate(e=>e.classList.contains('dark')),!dark)
      await page.locator('button[title]').click()
      loginState='success'; holdLogin=true; await page.locator('button[type=submit]').click()
      await page.waitForFunction(()=>document.querySelector('button[type=submit]').disabled)
      assert.ok(releaseLogin); releaseLogin()
      await page.locator('.smite-dashboard .smite-metric').first().waitFor()
      const measure=await page.evaluate(()=>({sidebar:document.querySelector('aside').getBoundingClientRect().width,heading:document.querySelector('.smite-dashboard h1').getBoundingClientRect().height,mainScroll:document.querySelector('main').scrollWidth,mainWidth:document.querySelector('main').clientWidth,root:getComputedStyle(document.documentElement).fontSize,headerHeight:document.querySelector('.smite-dashboard-heading').getBoundingClientRect().height,metricHeight:document.querySelector('.smite-metric').getBoundingClientRect().height}))
      assert.ok(measure.mainScroll<=measure.mainWidth+1,JSON.stringify(measure))
      if(width===1366 && language==='en' && dark) await page.screenshot({path:output+'/dashboard-1366-100.png'})
      if(width===1920 && language==='fa' && !dark) await page.screenshot({path:output+'/dashboard-1920-rtl-light.png'})
      if(width===390 && height===844 && language==='fa' && dark) await page.screenshot({path:output+'/dashboard-mobile-rtl.png',fullPage:true})
      for(const path of ['/nodes','/servers','/tunnels','/logs','/settings','/core-health']) {
        await page.goto(base+path, {waitUntil:'domcontentloaded'}); await page.locator('main').waitFor()
        const overflow=await page.locator('main').evaluate(e=>e.scrollWidth-e.clientWidth)
        assert.ok(overflow<=1,`${path} ${width} ${language}: overflow ${overflow}`)
        if(path==='/nodes' || path==='/servers') {
          await page.locator('.smite-page-actions button').last().click()
          const modal=page.locator('.smite-modal > div'); await modal.waitFor()
          const bounds=await modal.boundingBox(); assert.ok(bounds.x>=0 && bounds.x+bounds.width<=width+1 && bounds.y>=0 && bounds.y+bounds.height<=height+1)
        }
      }
      assert.deepEqual(errors,[])
      results.push({width,height,language,dark,login:initialLogin,loginWithError:g,dashboard:measure})
      await context.close()
    }
  }
  fs.writeFileSync(output+'/measurements.json',JSON.stringify(results,null,2))
  await browser.close()
  console.log('PASS: 16 viewport/language/theme combinations; centered Login, footer separation, MFA/error/theme/login, 7 routes without horizontal overflow. All API data are fixtures.')
})().catch(e=>{console.error(e);process.exit(1)})
