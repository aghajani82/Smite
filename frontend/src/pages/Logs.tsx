import { useEffect, useState, useRef } from 'react'
import api from '../api/client'
import { useLanguage } from '../contexts/LanguageContext'

interface LogEntry {
  timestamp: string
  level: string
  message: string
}

const Logs = () => {
  const { t } = useLanguage()
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [loading, setLoading] = useState(true)
  const logEndRef = useRef<HTMLDivElement>(null)
  const logContainerRef = useRef<HTMLDivElement>(null)
  const [shouldAutoScroll, setShouldAutoScroll] = useState(true)

  useEffect(() => {
    fetchLogs()
    const interval = setInterval(fetchLogs, 2000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    if (shouldAutoScroll && logEndRef.current) {
      logEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [logs, shouldAutoScroll])

  useEffect(() => {
    const container = logContainerRef.current
    if (!container) return

    const handleScroll = () => {
      const { scrollTop, scrollHeight, clientHeight } = container
      const isNearBottom = scrollHeight - scrollTop - clientHeight < 100
      setShouldAutoScroll(isNearBottom)
    }

    container.addEventListener('scroll', handleScroll)
    return () => container.removeEventListener('scroll', handleScroll)
  }, [])

  const fetchLogs = async () => {
    try {
      const response = await api.get('/logs?limit=100')
      setLogs(response.data.logs || [])
    } catch (error) {
      console.error('Failed to fetch logs:', error)
    } finally {
      setLoading(false)
    }
  }

  const getLevelColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'error':
        return 'text-red-600'
      case 'warning':
        return 'text-yellow-600'
      case 'info':
        return 'text-blue-600'
      default:
        return 'text-gray-600'
    }
  }

  if (loading && logs.length === 0) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 dark:border-blue-400 mb-4"></div>
          <p className="text-gray-500 dark:text-gray-400">Loading logs...</p>
        </div>
      </div>
    )
  }

  const getLevelColorDark = (level: string) => {
    switch (level.toLowerCase()) {
      case 'error':
        return 'text-red-400'
      case 'warning':
        return 'text-yellow-400'
      case 'info':
        return 'text-blue-400'
      default:
        return 'text-gray-300'
    }
  }

  return (
    <div className="w-full min-w-0">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">{t.logs.title}</h1>
        <p className="text-gray-500 dark:text-gray-400">{t.logs.subtitle}</p>
      </div>

      <div 
        ref={logContainerRef}
        className="bg-gray-900 dark:bg-black rounded-xl border border-gray-200 dark:border-gray-700 shadow-sm p-6 font-mono text-sm overflow-auto" 
        style={{ maxHeight: '70vh' }}
      >
        {logs.length === 0 ? (
          <div className="text-center py-12 text-gray-400">No logs available</div>
        ) : (
          logs.map((log, index) => (
            <div key={index} className="mb-1 hover:bg-gray-800/50 px-2 py-1 rounded">
              <span className="text-gray-500 dark:text-gray-400">[{log.timestamp}]</span>{' '}
              <span className={`${getLevelColor(log.level)} dark:${getLevelColorDark(log.level)}`}>[{log.level.toUpperCase()}]</span>{' '}
              <span className="text-gray-300 dark:text-gray-200">{log.message}</span>
            </div>
          ))
        )}
        <div ref={logEndRef} />
      </div>
    </div>
  )
}

export default Logs

