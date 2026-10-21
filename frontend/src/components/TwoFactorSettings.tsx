import { useEffect, useState } from 'react'
import api from '../api/client'
import { useAuth } from '../contexts/AuthContext'
import { useLanguage } from '../contexts/LanguageContext'

type Enrollment = { secret: string; otpauth_uri: string; qr_data_uri: string }
type Status = { enabled: boolean; pending: boolean }

const words = {
  en: {
    title: 'Two-step sign-in', enabled: 'Enabled', disabled: 'Not enabled',
    description: 'Use Google Authenticator or another authenticator app. Keep your recovery codes in a safe place.',
    password: 'Current password', code: '6-digit code or recovery code',
    start: 'Set up authenticator', setup: 'Add an account in Google Authenticator using this setup key.',
    open: 'Open in authenticator app', scan: 'Scan the QR with Google Authenticator. If you cannot scan, enter the setup key below.', confirm: 'Verify and enable',
    codes: 'Recovery codes — shown only once', save: 'Save all codes safely before leaving this page. Each code works once.',
    disable: 'Disable two-step sign-in', disableConfirm: 'Disable (requires password and code)',
    error: 'Could not complete this step', done: 'Two-step sign-in is enabled.',
    pending: 'Working…', retry: 'Refresh status',
    stored: 'The setup key and recovery codes are not stored in your browser after you leave.',
  },
  fa: {
    title: 'ورود دومرحله‌ای', enabled: 'فعال است', disabled: 'غیرفعال است',
    description: 'از Google Authenticator یا برنامه مشابه استفاده کنید. کدهای بازیابی را در جای امن نگه دارید.',
    password: 'رمز عبور فعلی', code: 'کد ۶ رقمی یا کد بازیابی',
    start: 'تنظیم برنامه Authenticator', setup: 'در Google Authenticator یک حساب با این کلید ایجاد کنید.',
    open: 'باز کردن در برنامه Authenticator', scan: 'QR را با Google Authenticator اسکن کن. اگر اسکن نشد، کلید زیر را دستی وارد کن.', confirm: 'تأیید و فعال‌سازی',
    codes: 'کدهای بازیابی — فقط همین یک بار نمایش داده می‌شوند', save: 'پیش از خروج، همه کدها را در جای امن ذخیره کنید. هر کد فقط یک بار قابل استفاده است.',
    disable: 'غیرفعال‌کردن ورود دومرحله‌ای', disableConfirm: 'غیرفعال‌سازی (با رمز و کد)',
    error: 'انجام عملیات موفق نبود', done: 'ورود دومرحله‌ای فعال شد.',
    pending: 'در حال انجام…', retry: 'بررسی دوباره وضعیت',
    stored: 'کلید راه‌اندازی و کدهای بازیابی پس از ترک صفحه در مرورگر نگهداری نمی‌شوند.',
  },
} as const

export default function TwoFactorSettings() {
  const { language } = useLanguage()
  const text = words[language]
  const { login } = useAuth()
  const [status, setStatus] = useState<Status | null>(null)
  const [enrollment, setEnrollment] = useState<Enrollment | null>(null)
  const [recovery, setRecovery] = useState<string[]>([])
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [showDisable, setShowDisable] = useState(false)

  const refresh = async () => {
    try {
      const response = await api.get<Status>('/auth/2fa/status')
      setStatus(response.data)
      setError('')
    } catch {
      setError(text.error)
    }
  }

  useEffect(() => { void refresh() }, [])

  const act = async (path: string, payload: Record<string, string>, after: (data: any) => void) => {
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const response = await api.post(path, payload)
      after(response.data)
    } catch (err: any) {
      const detail = err?.response?.data?.detail
      setError(typeof detail === 'string' ? detail : text.error)
    } finally {
      setBusy(false)
    }
  }

  const fieldClass = 'w-full rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-gray-800 px-3 py-2 text-slate-900 dark:text-white'
  const buttonClass = 'rounded-lg bg-blue-600 px-4 py-2 text-white font-medium disabled:opacity-50 hover:bg-blue-700'

  return (
    <section className="rounded-2xl border border-blue-100 dark:border-slate-700 bg-white dark:bg-gray-800 p-5 sm:p-6 space-y-4 shadow-sm">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-lg font-semibold text-slate-900 dark:text-white">{text.title}</h2>
        <span className="text-sm text-slate-600 dark:text-slate-300">
          {status ? (status.enabled ? text.enabled : text.disabled) : '…'}
        </span>
      </div>
      <p className="text-sm text-slate-600 dark:text-slate-300">{text.description}</p>
      {error && <p role="alert" className="text-sm text-red-700 dark:text-red-300">{error}</p>}
      {notice && <p role="status" className="text-sm text-green-700 dark:text-green-300">{notice}</p>}
      {!status && <button type="button" className={buttonClass} onClick={() => void refresh()}>{text.retry}</button>}

      {status && !status.enabled && recovery.length === 0 && (
        <div className="space-y-3">
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
            {text.password}
            <input type="password" autoComplete="current-password" value={password}
              onChange={event => setPassword(event.target.value)} className={fieldClass} />
          </label>
          {!enrollment ? (
            <button type="button" disabled={busy || !password} className={buttonClass}
              onClick={() => void act('/auth/2fa/setup', { password }, data => setEnrollment(data as Enrollment))}>
              {busy ? text.pending : text.start}
            </button>
          ) : (
            <div className="space-y-3 rounded-xl border border-blue-200 dark:border-slate-600 p-4">
              <p className="text-sm text-slate-700 dark:text-slate-200">{text.scan}</p>
              {/* Generated by our own Panel, never sent to a third-party QR service. */}
              <div className="flex justify-center rounded-xl bg-white p-4">
                <img src={enrollment.qr_data_uri} alt="Google Authenticator setup QR"
                  width={224} height={224} className="h-56 w-56" />
              </div>
              <p className="text-sm text-slate-700 dark:text-slate-200">{text.setup}</p>
              <code className="block select-all break-all rounded bg-slate-100 dark:bg-slate-900 p-3 text-sm text-slate-900 dark:text-slate-100" dir="ltr">{enrollment.secret}</code>
              <a className="block text-sm text-blue-600 dark:text-blue-300 underline" href={enrollment.otpauth_uri}>{text.open}</a>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
                {text.code}
                <input type="text" inputMode="numeric" autoComplete="one-time-code" value={code}
                  onChange={event => setCode(event.target.value)} className={fieldClass} />
              </label>
              <button type="button" className={buttonClass} disabled={busy || !password || !code.trim()}
                onClick={() => void act('/auth/2fa/enable', { password, code: code.trim() }, data => {
                  login(data.access_token, data.username)
                  setStatus({ enabled: true, pending: false })
                  setRecovery(data.recovery_codes)
                  setEnrollment(null)
                  setPassword('')
                  setCode('')
                  setNotice(text.done)
                })}>{busy ? text.pending : text.confirm}</button>
            </div>
          )}
        </div>
      )}

      {recovery.length > 0 && (
        <div className="space-y-3 rounded-xl border border-amber-300 dark:border-amber-700 p-4">
          <h3 className="font-semibold text-slate-900 dark:text-white">{text.codes}</h3>
          <p className="text-sm text-slate-700 dark:text-slate-300">{text.save}</p>
          <pre className="overflow-x-auto rounded-lg bg-slate-100 dark:bg-slate-900 p-3 font-mono text-sm text-slate-900 dark:text-white select-all" dir="ltr">{recovery.join('\n')}</pre>
          <p className="text-xs text-slate-600 dark:text-slate-400">{text.stored}</p>
        </div>
      )}

      {status?.enabled && recovery.length === 0 && (
        <div className="space-y-3">
          <button type="button" onClick={() => setShowDisable(!showDisable)}
            className="text-sm text-slate-600 dark:text-slate-300 underline">{text.disable}</button>
          {showDisable && (
            <div className="space-y-3 rounded-lg border border-red-200 dark:border-red-900 p-4">
              <label className="block text-sm text-slate-700 dark:text-slate-300">{text.password}
                <input className={fieldClass} type="password" autoComplete="current-password"
                  value={password} onChange={event => setPassword(event.target.value)} />
              </label>
              <label className="block text-sm text-slate-700 dark:text-slate-300">{text.code}
                <input className={fieldClass} type="text" autoComplete="one-time-code"
                  value={code} onChange={event => setCode(event.target.value)} />
              </label>
              <button className={buttonClass} disabled={busy || !password || !code.trim()} type="button"
                onClick={() => void act('/auth/2fa/disable', { password, code: code.trim() }, () => {
                  // All earlier access tokens are invalidated by the server.
                  // Disabling MFA already invalidated all JWT sessions.
                  // Clear browser state without retrying an invalid bearer.
                  localStorage.removeItem('token')
                  localStorage.removeItem('username')
                  delete api.defaults.headers.common['Authorization']
                  window.location.assign('/login')
                })}>{busy ? text.pending : text.disableConfirm}</button>
            </div>
          )}
        </div>
      )}
    </section>
  )
}
