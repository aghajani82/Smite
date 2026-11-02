import { ReactNode, useState, useEffect } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { LayoutDashboard, Network, FileText, Activity, Moon, Sun, Github, Menu, X, LogOut, Settings, Heart, Globe, Languages } from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import { useLanguage } from '../contexts/LanguageContext'

interface LayoutProps {
  children: ReactNode
}

const Layout = ({ children }: LayoutProps) => {
  const location = useLocation()
  const navigate = useNavigate()
  const { logout, username } = useAuth()
  const { language, setLanguage, dir, t } = useLanguage()
  const [darkMode, setDarkMode] = useState(() => {
    const saved = localStorage.getItem('darkMode')
    return saved ? JSON.parse(saved) : true
  })
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [showMoreTools, setShowMoreTools] = useState(true
  )
  const [version, setVersion] = useState('v0.1.0')
  const [loggingOut, setLoggingOut] = useState(false)
  const [logoutFailed, setLogoutFailed] = useState(false)

  const handleLogout = async () => {
    if (loggingOut) return
    setLoggingOut(true)
    setLogoutFailed(false)
    try {
      const revoked = await logout()
      if (revoked) {
        navigate('/login')
      } else {
        setLogoutFailed(true)
      }
    } finally {
      setLoggingOut(false)
    }
  }

  useEffect(() => {
    localStorage.setItem('darkMode', JSON.stringify(darkMode))
    if (darkMode) {
      document.documentElement.classList.add('dark')
    } else {
      document.documentElement.classList.remove('dark')
    }
  }, [darkMode])

  useEffect(() => {
    setSidebarOpen(false)
    if (['/core-health', '/logs', '/settings'].includes(location.pathname)) {
      setShowMoreTools(true)
    }
  }, [location.pathname])

  useEffect(() => {
    fetch('/api/status/version')
      .then(res => res.json())
      .then(data => {
        if (data.version) {
          setVersion(`v${data.version}`)
        }
      })
      .catch(() => {
        setVersion('v0.1.0')
      })
  }, [])
  
  const navItems = [
    { path: '/dashboard', label: t.navigation.dashboard, icon: LayoutDashboard },
    { path: '/nodes', label: t.navigation.nodes, icon: Network },
    { path: '/servers', label: t.navigation.servers, icon: Globe },
    { path: '/tunnels', label: t.navigation.tunnels, icon: Activity },
  ]
  const tools = [
    { path: '/core-health', label: t.navigation.coreHealth, icon: Heart },
    { path: '/logs', label: t.navigation.logs, icon: FileText },
    { path: '/settings', label: t.navigation.settings, icon: Settings },
  ]

  return (
    <div className="smite-shell min-h-screen bg-gray-50 dark:bg-gray-900" dir="ltr">
      <div className="flex h-screen">
        {/* Mobile Sidebar Overlay */}
        {sidebarOpen && (
          <div
            className="fixed inset-0 bg-black/50 z-40 lg:hidden"
            onClick={() => setSidebarOpen(false)}
          />
        )}

        {/* Sidebar - Always LTR regardless of language */}
        <aside
          dir="ltr"
          className={`fixed lg:static inset-y-0 left-0 w-60 bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700 flex flex-col z-50 transform transition-transform duration-300 ease-in-out ${
            sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
          }`}
        >
          {/* Existing navigation and routes remain unchanged. */}
          <div className="smite-brand">
            <span className="smite-brand-mark" aria-hidden="true">S</span>
            <span className="smite-brand-name text-lg font-bold text-slate-900 dark:text-white">Smite</span>
          </div>
          {/* Mobile sidebar close control; desktop menu starts at the top. */}
          <div className="lg:hidden flex justify-end px-3 pt-3">
            <button
              type="button"
              onClick={() => setSidebarOpen(false)}
              aria-label={language === 'fa' ? 'بستن منو' : 'Close menu'}
              className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-600 dark:text-gray-300"
            >
              <X size={20} />
            </button>
          </div>

          {/* Navigation: scroll only when the viewport is too short. */}
          <nav className="flex-1 min-h-0 p-3 space-y-1 overflow-y-auto">
            {navItems.map((item) => {
              const Icon = item.icon
              const isActive = location.pathname === item.path
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`flex items-center space-x-3 px-4 py-3 rounded-lg transition-all ${
                    isActive
                      ? 'smite-nav-active bg-teal-50 text-teal-700 dark:text-teal-300 shadow-sm'
                      : 'smite-nav-idle text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700/50'
                  }`}
                >
                  <Icon size={20} className={isActive ? 'text-teal-600 dark:text-teal-300' : ''} />
                  <span className="font-medium">{item.label}</span>
                </Link>
              )
            })}
            <div className="mt-5 pt-4 border-t border-gray-200 dark:border-gray-700">
              <button type="button" aria-expanded={showMoreTools} aria-controls="smite-extra-tools"
                onClick={() => setShowMoreTools(open => !open)}
                className="flex w-full items-center justify-between rounded-xl px-4 py-2.5 text-sm font-semibold text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-gray-700 focus-visible:outline focus-visible:outline-2 focus-visible:outline-blue-500">
                <span dir={dir}>{showMoreTools ? t.navigation.lessTools : t.navigation.moreTools}</span>
                <span aria-hidden="true">{showMoreTools ? '−' : '+'}</span>
              </button>
              {showMoreTools && (
                <div id="smite-extra-tools" className="mt-2 space-y-1">
                  {tools.map(item => {
                    const Icon = item.icon
                    const active = location.pathname === item.path
                    return (
                      <Link key={item.path} to={item.path}
                        aria-current={active ? 'page' : undefined}
                        className={`flex items-center gap-3 px-4 py-2.5 rounded-xl text-sm transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-blue-500 ${
                          active ? 'smite-nav-active bg-teal-50 text-teal-700 dark:text-teal-300'
                            : 'smite-nav-idle text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-gray-700'
                        }`}>
                        <Icon size={18} aria-hidden="true" />
                        <span dir={dir}>{item.label}</span>
                      </Link>
                    )
                  })}
                </div>
              )}
            </div>
          </nav>
          
          {/* Sidebar Footer */}
          <div className="smite-shell-footer p-4 border-t border-gray-200 dark:border-gray-700 space-y-2">
            <div className="space-y-2">
              <div className="flex items-center justify-between px-4 py-2">
                <button
                  onClick={() => setDarkMode(!darkMode)}
                  className="flex items-center gap-2 text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white transition-colors"
                >
                  {darkMode ? <Sun size={18} /> : <Moon size={18} />}
                  <span className="text-sm font-medium">{darkMode ? t.navigation.light : t.navigation.dark}</span>
                </button>
                <button
                  onClick={() => setLanguage(language === 'en' ? 'fa' : 'en')}
                  className="flex items-center gap-2 text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white transition-colors"
                  title={language === 'en' ? 'Switch to Farsi' : 'Switch to English'}
                >
                  <Languages size={18} />
                  <span className="text-sm font-medium">{language === 'en' ? 'EN' : 'FA'}</span>
                </button>
              </div>
              <div className="px-4">
                <button
                  onClick={() => void handleLogout()}
                  disabled={loggingOut}
                  title={language === 'fa' ? 'خروج از تمام دستگاه‌ها' : 'Sign out on all devices'}
                  className="w-full flex items-center justify-center gap-2 text-red-600 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300 transition-colors disabled:opacity-50"
                >
                  <LogOut size={18} />
                  <span className="text-sm font-medium">{loggingOut ? (language === 'fa' ? 'در حال خروج…' : 'Signing out…') : t.navigation.logout}</span>
                </button>
                <p className="mt-1 text-center text-xs text-gray-500 dark:text-gray-400">
                  {language === 'fa' ? 'خروج از همه دستگاه‌ها' : 'Sign out on all devices'}
                </p>
                {logoutFailed && (
                  <p role="alert" className="mt-2 text-xs text-red-600 dark:text-red-400 text-center">
                    {language === 'fa'
                      ? 'ارتباط با سرور برقرار نشد. خروج انجام نشده؛ دوباره تلاش کنید.'
                      : 'Server unreachable. Sign-out was not completed; please retry.'}
                  </p>
                )}
              </div>
            </div>
            <div className="flex flex-col items-center gap-2 text-xs text-gray-500 dark:text-gray-400 pt-2 border-t border-gray-200 dark:border-gray-700">
              <div className="flex items-center gap-1 flex-wrap justify-center">
                <span>Made with</span>
                <span className="text-red-500">❤️</span>
                <span>by</span>
                <a 
                  href="https://github.com/zZedix" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-blue-600 dark:text-blue-400 hover:underline"
                >
                  zZedix
                </a>
              </div>
              <div className="flex items-center gap-2">
                <span>{version}</span>
                <a 
                  href="https://github.com/zZedix/Smite" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="hover:text-gray-700 dark:hover:text-gray-300 transition-colors"
                  title="GitHub Repository"
                >
                  <Github size={14} />
                </a>
              </div>
            </div>
          </div>
        </aside>

        {/* Main Content */}
        <main className="smite-ambient-panel flex-1 overflow-auto bg-gray-50 dark:bg-gray-900" dir={dir}>
          {/* Mobile Header */}
          <div className="smite-shell-header lg:hidden sticky top-0 z-30 bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 px-4 py-3 flex items-center justify-between shadow-sm">
            <button
              onClick={() => setSidebarOpen(true)}
              className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-600 dark:text-gray-300"
            >
              <Menu size={24} />
            </button>
            <h1 className="text-lg font-bold bg-gradient-to-r from-blue-600 to-indigo-600 dark:from-blue-400 dark:to-indigo-400 bg-clip-text text-transparent">Smite</h1>
            <div className="w-10" />
          </div>
          
          <div className="hidden lg:flex items-center justify-between border-b border-gray-200 dark:border-slate-700/70 px-6 py-4 text-sm">
            <span className="font-semibold text-slate-700 dark:text-slate-200">Smite Web Panel</span>
            <span className="text-slate-500 dark:text-slate-400">{username || 'Smite'}</span>
          </div>
          <div className="p-4 sm:p-6 lg:p-8">
            {children}
          </div>
        </main>
      </div>
    </div>
  )
}

export default Layout
