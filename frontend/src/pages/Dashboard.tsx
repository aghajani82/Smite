import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Activity, ArrowRight, CircleAlert, Cpu, MemoryStick, Network, RefreshCw, Server, ShieldCheck } from 'lucide-react'
import { useLanguage } from '../contexts/LanguageContext'
import api from '../api/client'

interface Status {
  system: {
    cpu_percent: number
    memory_percent: number
    memory_total_gb: number
    memory_used_gb: number
  }
  tunnels: { total: number; active: number }
  nodes: { total: number; active: number }
}

interface RegisteredNode {
  metadata?: { role?: string }
}

const percent = (value: number) => Math.max(0, Math.min(100, Number.isFinite(value) ? value : 0))
const number = (value: number) => Number.isFinite(value) ? value : 0

const Dashboard = () => {
  const { t, dir, language } = useLanguage()
  const [status, setStatus] = useState<Status | null>(null)
  const [registered, setRegistered] = useState<{ iran: boolean; foreign: boolean } | null>(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState(false)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const [reload, setReload] = useState(0)

  useEffect(() => {
    let mounted = true
    const fetchData = async () => {
      if (mounted) setRefreshing(true)
      try {
        const response = await api.get<Status>('/status')
        if (!mounted) return
        setStatus(response.data)
        setError(false)
        setLastUpdated(new Date())
      } catch {
        // Preserve the last-known values but show that they may be stale.
        if (mounted) setError(true)
      } finally {
        if (mounted) {
          setLoading(false)
          setRefreshing(false)
        }
      }
      try {
        const response = await api.get<RegisteredNode[]>('/nodes')
        if (!mounted) return
        const nodes = Array.isArray(response.data) ? response.data : []
        setRegistered({
          iran: nodes.some(node => node.metadata?.role === 'iran'),
          foreign: nodes.some(node => node.metadata?.role === 'foreign'),
        })
      } catch {
        if (mounted) setRegistered(null)
      }
    }
    void fetchData()
    const interval = setInterval(fetchData, 15000)
    return () => {
      mounted = false
      clearInterval(interval)
    }
  }, [reload])

  const hasIran = registered?.iran === true
  const hasForeign = registered?.foreign === true
  const next = registered === null
    ? { label: t.dashboard.viewNodes, path: '/nodes' }
    : !hasIran
      ? { label: t.dashboard.addNode, path: '/nodes?add=true' }
      : !hasForeign
        ? { label: t.dashboard.addServer, path: '/servers?add=true' }
        : { label: t.dashboard.createNewTunnel, path: '/tunnels?create=true' }

  const steps = [
    { number: 1, label: t.dashboard.stepIran, done: hasIran, path: '/nodes' },
    { number: 2, label: t.dashboard.stepForeign, done: hasForeign, path: '/servers' },
    { number: 3, label: t.dashboard.stepTunnel, done: Boolean(status && status.tunnels.total > 0), path: '/tunnels' },
  ]

  return (
    <div className="w-full max-w-6xl mx-auto space-y-6 pb-8" dir={dir}>
      <header className="relative overflow-hidden rounded-3xl bg-gradient-to-br from-slate-900 via-blue-950 to-indigo-900 text-white p-6 sm:p-8 shadow-xl">
        <div className="absolute -top-20 -end-20 w-64 h-64 rounded-full bg-blue-400/10 blur-2xl pointer-events-none" />
        <div className="relative flex flex-col sm:flex-row sm:items-start sm:justify-between gap-5">
          <div>
            <div className="flex items-center gap-2 text-blue-200 text-sm font-medium mb-3">
              <ShieldCheck size={18} aria-hidden="true" />
              <span>SMITE</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-bold tracking-tight">{t.dashboard.title}</h1>
            <p className="mt-2 text-sm sm:text-base text-blue-100/85">{t.dashboard.simpleSubtitle}</p>
            <div aria-live="polite" role="status" className="mt-4 flex flex-wrap items-center gap-2 text-sm">
              <span className={"inline-flex items-center gap-2 rounded-full px-3 py-1.5 border " + (
                error ? "bg-amber-100/10 border-amber-200/30 text-amber-100" :
                status ? "bg-emerald-100/10 border-emerald-200/30 text-emerald-100" :
                "bg-white/10 border-white/20 text-white"
              )}>
                <span className={"h-2 w-2 rounded-full " + (error ? "bg-amber-300" : status ? "bg-emerald-300" : "bg-blue-300")} />
                {error ? t.dashboard.apiUnavailable : status ? t.dashboard.apiReachable : t.dashboard.loadingDashboard}
              </span>
              {lastUpdated && <span className="text-blue-200 text-xs">{t.dashboard.lastUpdated}: {lastUpdated.toLocaleTimeString(language === 'fa' ? 'fa-IR' : 'en-US')}</span>}
            </div>
          </div>
          <button
            type="button"
            onClick={() => setReload(x => x + 1)}
            disabled={refreshing}
            className="inline-flex shrink-0 items-center justify-center gap-2 rounded-xl border border-white/20 bg-white/10 px-4 py-2.5 text-sm font-medium hover:bg-white/20 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-white disabled:opacity-60"
          >
            <RefreshCw size={16} className={refreshing ? 'animate-spin' : ''} aria-hidden="true" />
            {t.dashboard.refresh}
          </button>
        </div>
      </header>

      {error && (
        <section role="alert" className="flex items-start gap-3 rounded-2xl border border-amber-300/50 bg-amber-50 dark:bg-amber-900/20 p-4 text-amber-900 dark:text-amber-200">
          <CircleAlert size={20} className="shrink-0 mt-0.5" aria-hidden="true" />
          <p className="text-sm">{t.dashboard.apiErrorHelp}</p>
        </section>
      )}

      {loading && !status ? (
        <div className="py-16 text-center text-slate-500 dark:text-slate-400" aria-live="polite">
          <RefreshCw size={24} className="mx-auto mb-3 animate-spin" aria-hidden="true" />
          {t.dashboard.loadingDashboard}
        </div>
      ) : (
        <>
          {status && (
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <Metric icon={Server} title={t.dashboard.totalNodes} count={status.nodes.total}
                secondary={String(status.nodes.active) + ' ' + t.dashboard.active} />
              <Metric icon={Network} title={t.dashboard.totalTunnels} count={status.tunnels.total}
                secondary={String(status.tunnels.active) + ' ' + t.dashboard.active} />
              <Metric icon={Activity} title={t.dashboard.overview}
                count={status.tunnels.active} secondary={t.dashboard.activeTunnels} />
            </div>
          )}
          <div className="grid grid-cols-1 lg:grid-cols-5 gap-5">
            <section className="lg:col-span-3 rounded-2xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-gray-800 shadow-sm p-5 sm:p-6">
              <h2 className="text-lg font-semibold text-slate-900 dark:text-white">{t.dashboard.simpleSteps}</h2>
              <p className="text-sm text-slate-500 dark:text-slate-400 mt-1 mb-5">{t.dashboard.simpleStepsHelp}</p>
              <ol className="space-y-3">
                {steps.map(step => (
                  <li key={step.number}>
                    <Link to={step.path} className="flex items-center gap-3 rounded-xl border border-slate-100 dark:border-slate-700 p-3.5 hover:bg-slate-50 dark:hover:bg-slate-700/40 focus-visible:outline focus-visible:outline-2 focus-visible:outline-blue-500">
                      <span aria-hidden="true" className={"flex w-8 h-8 shrink-0 items-center justify-center rounded-full text-sm font-bold " + (
                        registered !== null && step.done
                          ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300"
                          : "bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-200"
                      )}>{step.number}</span>
                      <span className="flex-1 font-medium text-slate-800 dark:text-slate-100">{step.label}</span>
                      <span className="text-xs text-slate-500 dark:text-slate-400">{registered === null ? t.dashboard.statusUnknown : step.done ? t.dashboard.added : t.dashboard.notAdded}</span>
                      <ArrowRight size={16} className={"text-slate-400 " + (dir === 'rtl' ? 'rotate-180' : '')} aria-hidden="true" />
                    </Link>
                  </li>
                ))}
              </ol>
              <Link to={next.path} className="mt-5 flex items-center justify-center gap-2 rounded-xl bg-blue-600 px-4 py-3 text-white font-semibold hover:bg-blue-700 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600">
                {next.label}
                <ArrowRight size={18} className={dir === 'rtl' ? 'rotate-180' : ''} aria-hidden="true" />
              </Link>
            </section>
            <section className="lg:col-span-2 rounded-2xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-gray-800 shadow-sm p-5 sm:p-6">
              <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-1">{t.dashboard.systemResources}</h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mb-5">{t.dashboard.currentUsage}</p>
              {status ? (
                <div className="space-y-6">
                  <Resource icon={Cpu} name={t.dashboard.cpuUsage} value={number(status.system.cpu_percent)} />
                  <Resource icon={MemoryStick} name={t.dashboard.memoryUsage} value={number(status.system.memory_percent)} />
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    {number(status.system.memory_used_gb).toFixed(1)} / {number(status.system.memory_total_gb).toFixed(1)} GB
                  </p>
                </div>
              ) : (
                <p className="text-sm text-slate-500 dark:text-slate-400">{t.dashboard.noData}</p>
              )}
            </section>
          </div>
        </>
      )}
    </div>
  )
}

type Icon = typeof Server

const Metric = ({ icon: IconComponent, title, count, secondary }: { icon: Icon; title: string; count: number; secondary: string }) => (
  <div className="rounded-2xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-gray-800 shadow-sm p-5">
    <div className="flex items-center gap-3 mb-3">
      <span className="rounded-xl bg-blue-50 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300 p-2.5">
        <IconComponent size={19} aria-hidden="true" />
      </span>
      <h2 className="text-sm text-slate-600 dark:text-slate-300 font-medium">{title}</h2>
    </div>
    <p className="text-3xl font-bold tabular-nums text-slate-900 dark:text-white">{count}</p>
    <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{secondary}</p>
  </div>
)

const Resource = ({ icon: IconComponent, name, value }: { icon: Icon; name: string; value: number }) => (
  <div>
    <div className="flex items-center gap-2 text-sm mb-2">
      <IconComponent size={16} className="text-slate-500 dark:text-slate-400" aria-hidden="true" />
      <span className="flex-1 text-slate-700 dark:text-slate-200">{name}</span>
      <span className="font-semibold tabular-nums text-slate-900 dark:text-white">{percent(value).toFixed(1)}%</span>
    </div>
    <div role="progressbar" aria-label={name} aria-valuenow={percent(value)} aria-valuemin={0} aria-valuemax={100}
      className="h-2.5 rounded-full overflow-hidden bg-slate-100 dark:bg-slate-700">
      <div className="h-full bg-blue-500 rounded-full transition-all duration-300" style={{ width: percent(value) + '%' }} />
    </div>
  </div>
)

export default Dashboard
