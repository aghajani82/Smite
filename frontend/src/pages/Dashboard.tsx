import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Activity, ArrowRight, AlertCircle, CheckCircle2, Cpu, FileText, HeartPulse, MemoryStick, Network, RefreshCw, Server, ShieldCheck } from 'lucide-react'
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

interface LogEntry {
  timestamp?: string
  level?: string
  message?: string
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
  const [recentLogs, setRecentLogs] = useState<LogEntry[] | null>(null)

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
        if (nodes.some(node => !node.metadata?.role)) {
          // An older, untyped registration cannot establish a server role.
          // Show "unverified" instead of guessing IR/KH readiness.
          setRegistered(null)
        } else {
          setRegistered({
            iran: nodes.some(node => node.metadata?.role === 'iran'),
            foreign: nodes.some(node => node.metadata?.role === 'foreign'),
          })
        }
      } catch {
        if (mounted) setRegistered(null)
      }
      // Reuse the existing Logs endpoint; no new audit or monitoring API.
      try {
        const response = await api.get<{ logs: LogEntry[] }>('/logs?limit=5')
        if (mounted) setRecentLogs(Array.isArray(response.data?.logs) ? response.data.logs : [])
      } catch {
        if (mounted) setRecentLogs(null)
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

  const completeCount = registered === null ? null : steps.filter(s => s.done).length
  const textStatus = (value: boolean | null) => value === null ? t.dashboard.statusUnknown : value ? t.dashboard.added : t.dashboard.notAdded

  return (
    <div className="smite-dashboard w-full max-w-7xl mx-auto space-y-5 pb-8" dir={dir}>
      <header className="smite-dashboard-heading rounded-2xl bg-slate-100 dark:bg-slate-800 p-5 sm:p-7">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-teal-600 dark:text-teal-300 text-sm mb-2">
              <ShieldCheck size={17} aria-hidden="true" /><span>SMITE</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 dark:text-white">{t.dashboard.title}</h1>
            <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">{t.dashboard.simpleSubtitle}</p>
          </div>
          <button type="button" onClick={() => setReload(x => x + 1)} disabled={refreshing}
            className="flex items-center gap-2 rounded-lg border border-teal-500/40 px-3 py-2 text-sm text-teal-700 dark:text-teal-200 hover:bg-teal-500/10 focus-visible:outline focus-visible:outline-2 focus-visible:outline-teal-400 disabled:opacity-60">
            <RefreshCw size={15} className={refreshing ? 'animate-spin' : ''} aria-hidden="true" />
            {t.dashboard.refresh}
          </button>
        </div>
        <div className="mt-5 flex flex-wrap items-center gap-3 text-sm" aria-live="polite" role="status">
          <div className={'flex items-center gap-2 rounded-xl border px-4 py-2 ' + (
            error ? 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-200' :
            status ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-200' :
            'border-slate-400/40 bg-slate-500/10 text-slate-500 dark:text-slate-300'
          )}>
            {error ? <AlertCircle size={17} aria-hidden="true" /> : <CheckCircle2 size={17} aria-hidden="true" />}
            {error ? t.dashboard.apiUnavailable : status ? t.dashboard.apiReachable : t.dashboard.loadingDashboard}
          </div>
          {lastUpdated && <span className="text-xs text-slate-500 dark:text-slate-400">{t.dashboard.lastUpdated}: {lastUpdated.toLocaleTimeString(language === 'fa' ? 'fa-IR' : 'en-US')}</span>}
        </div>
      </header>

      {error && (
        <section role="alert" className="rounded-xl border border-amber-500/40 bg-amber-100/60 dark:bg-amber-900/20 px-4 py-3 text-sm text-amber-900 dark:text-amber-200">
          {t.dashboard.apiErrorHelp}
        </section>
      )}

      {loading && !status ? (
        <div className="py-16 text-center text-slate-500 dark:text-slate-300" aria-live="polite">
          <RefreshCw size={24} className="mx-auto mb-3 animate-spin" aria-hidden="true" />
          {t.dashboard.loadingDashboard}
        </div>
      ) : (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-3">
            <Metric icon={Cpu} title={t.dashboard.cpuUsage}
              count={status && !error ? Math.round(number(status.system.cpu_percent)) + '%' : '—'}
              secondary={status && !error ? t.dashboard.currentUsage : t.dashboard.statusUnknown} />
            <Metric icon={MemoryStick} title={t.dashboard.memoryUsage}
              count={status && !error ? Math.round(number(status.system.memory_percent)) + '%' : '—'}
              secondary={status && !error ? number(status.system.memory_used_gb).toFixed(1) + ' / ' + number(status.system.memory_total_gb).toFixed(1) + ' GB' : t.dashboard.statusUnknown} />
            <Metric icon={Server} title={t.dashboard.totalNodes}
              count={status && !error ? status.nodes.total : '—'}
              secondary={status && !error ? String(status.nodes.active) + ' ' + t.dashboard.active : t.dashboard.statusUnknown} />
            <Metric icon={Network} title={t.dashboard.totalTunnels}
              count={status && !error ? status.tunnels.total : '—'}
              secondary={status && !error ? String(status.tunnels.active) + ' ' + t.dashboard.active : t.dashboard.statusUnknown} />
            <Metric icon={Activity} title="API"
              count={status && !error ? 'Online' : '—'}
              secondary={error ? t.dashboard.apiUnavailable : status ? t.dashboard.apiReachable : t.dashboard.statusUnknown} />
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-5 gap-4">
            <section className="smite-panel xl:col-span-3 rounded-2xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-gray-800 p-5 sm:p-6">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h2 className="flex items-center gap-2 text-lg font-semibold text-slate-900 dark:text-white">
                  <ShieldCheck size={20} className="text-teal-600 dark:text-teal-300" aria-hidden="true" />
                  {t.dashboard.simpleSteps}
                </h2>
                <span className="text-xs text-slate-500 dark:text-slate-400">
                  {completeCount === null ? t.dashboard.statusUnknown : String(completeCount) + ' / ' + String(steps.length)}
                </span>
              </div>
              <p className="text-sm text-slate-500 dark:text-slate-400 mt-1 mb-4">{t.dashboard.simpleStepsHelp}</p>
              <div className="mb-5 h-2 overflow-hidden rounded-full bg-slate-200 dark:bg-slate-600"
                role="progressbar" aria-label={t.dashboard.simpleSteps}
                aria-valuenow={completeCount === null ? undefined : completeCount}
                aria-valuemin={0} aria-valuemax={steps.length}>
                <div className="h-full rounded-full bg-teal-400 transition-all duration-300"
                  style={{ width: (completeCount === null ? 0 : 100 * completeCount / steps.length) + '%' }} />
              </div>
              <ol className="space-y-2">
                {steps.map(step => (
                  <li key={step.number}>
                    <Link to={step.path}
                      className="flex items-center gap-3 rounded-xl border border-slate-200 dark:border-slate-600 p-3 hover:bg-teal-500/5 focus-visible:outline focus-visible:outline-2 focus-visible:outline-teal-400">
                      <span className={'flex w-8 h-8 shrink-0 items-center justify-center rounded-lg text-sm font-bold ' + (
                        registered !== null && step.done
                          ? 'smite-step-done bg-emerald-100 text-emerald-700 dark:text-teal-200'
                          : 'bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-200'
                      )}>{step.number}</span>
                      <span className="flex-1 font-medium text-slate-800 dark:text-slate-100">{step.label}</span>
                      <span className="text-xs text-slate-500 dark:text-slate-400">{registered === null ? t.dashboard.statusUnknown : step.done ? t.dashboard.added : t.dashboard.notAdded}</span>
                      <ArrowRight size={16} className={'text-teal-500 ' + (dir === 'rtl' ? 'rotate-180' : '')} aria-hidden="true" />
                    </Link>
                  </li>
                ))}
              </ol>
              <Link to={next.path}
                className="smite-primary-button mt-4 flex items-center justify-center gap-2 rounded-lg bg-teal-500 px-4 py-3 font-semibold text-slate-950 hover:bg-teal-400 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-teal-500">
                {next.label} <ArrowRight size={18} className={dir === 'rtl' ? 'rotate-180' : ''} aria-hidden="true" />
              </Link>
            </section>

            <section className="smite-panel xl:col-span-2 rounded-2xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-gray-800 p-5 sm:p-6">
              <h2 className="flex items-center gap-2 text-lg font-semibold text-slate-900 dark:text-white mb-2">
                <HeartPulse size={20} className="text-teal-600 dark:text-teal-300" aria-hidden="true" />
                {t.navigation.coreHealth}
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">{t.dashboard.apiErrorHelp}</p>
              <HealthLine label="API" value={!error && status ? t.dashboard.apiReachable : t.dashboard.statusUnknown} known={!error && Boolean(status)} />
              <HealthLine label={t.navigation.nodes} value={textStatus(registered === null ? null : registered.iran)} known={registered !== null && registered.iran} />
              <HealthLine label={t.navigation.servers} value={textStatus(registered === null ? null : registered.foreign)} known={registered !== null && registered.foreign} />
              <HealthLine label={t.navigation.tunnels}
                value={status && !error ? String(status.tunnels.active) + ' ' + t.dashboard.active : t.dashboard.statusUnknown}
                known={Boolean(status && !error && status.tunnels.active > 0)} />
              <Link to="/core-health" className="mt-5 inline-flex items-center gap-2 text-sm font-semibold text-teal-700 dark:text-teal-300 hover:underline">
                {t.navigation.coreHealth} <ArrowRight size={16} className={dir === 'rtl' ? 'rotate-180' : ''} aria-hidden="true" />
              </Link>
            </section>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            <section className="smite-panel rounded-2xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-gray-800 p-5 sm:p-6">
              <div className="mb-4 flex flex-wrap justify-between items-center gap-2">
                <h2 className="flex items-center gap-2 text-lg font-semibold text-slate-900 dark:text-white">
                  <FileText size={20} className="text-teal-600 dark:text-teal-300" aria-hidden="true" />
                  {t.navigation.logs}
                </h2>
                <Link to="/logs" className="text-sm text-teal-700 dark:text-teal-300 hover:underline">
                  {t.navigation.logs} <span aria-hidden="true">→</span>
                </Link>
              </div>
              {recentLogs === null ? (
                <p className="text-sm text-slate-500 dark:text-slate-400">{t.dashboard.noData}</p>
              ) : recentLogs.length === 0 ? (
                <p className="text-sm text-slate-500 dark:text-slate-400">{t.dashboard.noData}</p>
              ) : (
                <ul className="divide-y divide-slate-200 dark:divide-slate-600">
                  {recentLogs.slice(-5).reverse().map((entry, i) => (
                    <li key={i} className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-3 py-2.5 text-xs">
                      <span className="text-slate-500 dark:text-slate-400 whitespace-nowrap">{entry.timestamp || '—'}</span>
                      <span className="flex-1 text-slate-700 dark:text-slate-200 break-all">{entry.message || '—'}</span>
                    </li>
                  ))}
                </ul>
              )}
            </section>
            <section className="smite-panel rounded-2xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-gray-800 p-5 sm:p-6">
              <h2 className="flex items-center gap-2 text-lg font-semibold text-slate-900 dark:text-white mb-2">
                <Activity size={20} className="text-teal-600 dark:text-teal-300" aria-hidden="true" />
                {t.dashboard.systemResources}
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">{t.dashboard.currentUsage}</p>
              {status && !error ? (
                <>
                  <div className="smite-resource-gauges">
                    <Gauge name={t.dashboard.cpuUsage} value={number(status.system.cpu_percent)} />
                    <Gauge name={t.dashboard.memoryUsage} value={number(status.system.memory_percent)} />
                  </div>
                  <div className="space-y-4">
                    <Resource icon={Cpu} name={t.dashboard.cpuUsage} value={number(status.system.cpu_percent)} />
                    <Resource icon={MemoryStick} name={t.dashboard.memoryUsage} value={number(status.system.memory_percent)} />
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      {number(status.system.memory_used_gb).toFixed(1)} / {number(status.system.memory_total_gb).toFixed(1)} GB
                    </p>
                  </div>
                </>
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

const Metric = ({ icon: IconComponent, title, count, secondary }: { icon: Icon; title: string; count: number | string; secondary: string }) => (
  <div className="smite-metric rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-gray-800 p-4">
    <div className="mb-3 flex items-center gap-2">
      <span className="smite-metric-icon rounded-lg bg-teal-50 p-2 text-teal-700 dark:bg-teal-900/20 dark:text-teal-300">
        <IconComponent size={18} aria-hidden="true" />
      </span>
      <h2 className="text-sm font-medium text-slate-600 dark:text-slate-200">{title}</h2>
    </div>
    <p className="text-2xl font-bold tabular-nums text-slate-900 dark:text-white">{count}</p>
    <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{secondary}</p>
  </div>
)

const HealthLine = ({ label, value, known }: { label: string; value: string; known: boolean }) => (
  <div className="flex items-center gap-2 border-b border-slate-200 dark:border-slate-600 py-3 text-sm">
    <span className={'h-2 w-2 shrink-0 rounded-full ' + (known ? 'bg-emerald-400' : 'bg-slate-400')} />
    <span className="flex-1 text-slate-700 dark:text-slate-200">{label}</span>
    <span className={known ? 'text-emerald-700 dark:text-teal-300' : 'text-slate-500 dark:text-slate-400'}>{value}</span>
  </div>
)

const Gauge = ({ name, value }: { name: string; value: number }) => (
  <div className="text-center">
    <div className="smite-ring" role="img" aria-label={name + ': ' + percent(value).toFixed(1) + '%'}
      style={{ background: 'conic-gradient(#20dbc9 ' + percent(value) + '%, #34474f 0)' }}>
      <div className="smite-ring-inner">
        <span className="text-xl">{Math.round(percent(value))}%</span>
        <span className="smite-ring-caption">{name}</span>
      </div>
    </div>
  </div>
)

const Resource = ({ icon: IconComponent, name, value }: { icon: Icon; name: string; value: number }) => (
  <div>
    <div className="mb-2 flex items-center gap-2 text-sm">
      <IconComponent size={16} className="text-teal-600 dark:text-teal-300" aria-hidden="true" />
      <span className="flex-1 text-slate-700 dark:text-slate-200">{name}</span>
      <span className="font-semibold tabular-nums text-slate-900 dark:text-white">{percent(value).toFixed(1)}%</span>
    </div>
    <div role="progressbar" aria-label={name} aria-valuenow={percent(value)} aria-valuemin={0} aria-valuemax={100}
      className="h-2.5 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-700">
      <div className="h-full rounded-full bg-teal-400 transition-all duration-300" style={{ width: percent(value) + '%' }} />
    </div>
  </div>
)

export default Dashboard
