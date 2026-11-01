// Offline contract for the compact sidebar. No browser/network/server is touched.
const test = require('node:test')
const assert = require('node:assert/strict')
const { readFileSync } = require('node:fs')
const { join } = require('node:path')

const layout = readFileSync(join(__dirname, '../src/components/Layout.tsx'), 'utf8')

test('large sidebar brand block is removed and navigation begins at the top', () => {
  assert.doesNotMatch(layout, /SmiteLogoDark|SmiteLogoLight|Smite Logo|Sidebar Header/)
  assert.doesNotMatch(layout, /className="relative h-24 w-24"/)
  assert.match(layout, /<nav className="flex-1 min-h-0 p-3 space-y-1 overflow-y-auto">/)
  assert.ok(layout.indexOf('Navigation: scroll only') < layout.indexOf('navItems.map'))
  assert.match(layout, /navItems\.map/)
  assert.match(layout, /showMoreTools &&/)
})

test('short mobile viewports remain accessible without sacrificing controls', () => {
  assert.match(layout, /lg:hidden flex justify-end px-3 pt-3/)
  assert.match(layout, /aria-label=\{language === 'fa' \? 'بستن منو' : 'Close menu'\}/)
  assert.match(layout, /onClick=\{\(\) => setSidebarOpen\(false\)\}/)
  assert.match(layout, /overflow-y-auto/)
  assert.match(layout, /setDarkMode\(!darkMode\)/)
  assert.match(layout, /setLanguage\(language === 'en' \? 'fa' : 'en'\)/)
  assert.match(layout, /handleLogout\(\)/)
  assert.match(layout, /logoutFailed/)
})
