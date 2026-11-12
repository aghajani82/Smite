import { useEffect, useRef, useState } from 'react'
import api from '../api/client'
import { installationPacket, validInstallDomain, type InstallNode, type InstallationGrant } from './foreignInstallContract'

export function useForeignInstallAvailability() {
  const [ready, setReady] = useState(false)
  useEffect(() => {
    const abort = new AbortController()
    api.get('/foreign-install/capabilities', { signal: abort.signal,
      headers: { 'Cache-Control': 'no-store' } }).then(({ data }) => {
      if (!abort.signal.aborted) setReady(data.foreign_install_enabled === true &&
        data.origin_trust_ready === true && data.protocol === 'smi1' && window.location.protocol === 'https:' &&
        ['', '443'].includes(new URL(window.location.origin).port))
    }).catch(() => { if (!abort.signal.aborted) setReady(false) })
    return () => abort.abort()
  }, [])
  return ready
}

/** Secret is confined to the mounted dialog. Closing does not revoke the grant. */
export function ForeignInstallDialog({ node, onClose, onReserved }: {
  node?: InstallNode; onClose: () => void; onReserved: () => void
}) {
  const [reserved, setReserved] = useState<InstallNode | undefined>(node)
  const [name, setName] = useState(node?.name || '')
  const [domain, setDomain] = useState('')
  const [packet, setPacket] = useState('')
  const [expires, setExpires] = useState(0)
  const [left, setLeft] = useState(0)
  const [busy, setBusy] = useState(false)
  const [uncertain, setUncertain] = useState(false)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)
  const request = useRef<AbortController | null>(null)
  useEffect(() => () => request.current?.abort(), [])
  useEffect(() => {
    if (!expires) return
    const tick = () => {
      const seconds = Math.max(0, Math.ceil((expires * 1000 - Date.now()) / 1000))
      setLeft(seconds)
      if (!seconds) { setPacket(''); setExpires(0); setCopied(false) }
    }
    tick()
    const timer = window.setInterval(tick, 1000)
    return () => window.clearInterval(timer)
  }, [expires])

  const issue = async () => {
    if (request.current || uncertain || packet) return
    const normalized = domain.trim().toLowerCase()
    if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{1,63}$/.test(name) || !validInstallDomain(normalized)) {
      setError('Enter a valid Node name and domain only, without https:// or a port.'); return
    }
    const abort = new AbortController()
    request.current = abort
    setBusy(true); setError(''); setCopied(false)
    let current = reserved
    try {
      if (!current) {
        // A lost reservation reply must be reconciled from the list, not retried.
        setUncertain(true)
        const { data } = await api.post('/node-pairing/reserve', { name, role: 'foreign' }, {
          signal: abort.signal, headers: { 'Cache-Control': 'no-store' },
        })
        if (abort.signal.aborted) return
        if (!/^[A-Za-z0-9_-]{8,80}$/.test(data.node_id) || data.name !== name || data.status !== 'pending') throw new Error('Invalid reservation')
        current = { id: data.node_id, name: data.name }
        setReserved(current); setUncertain(false); onReserved()
      }
      const { data } = await api.post<InstallationGrant>('/foreign-install/issue', {
        node_id: current.id, node_name: current.name, domain: normalized, ttl_seconds: 7200,
      }, { signal: abort.signal, headers: { 'Cache-Control': 'no-store' } })
      if (abort.signal.aborted) return
      setPacket(installationPacket(data, current, normalized, window.location.origin))
      setExpires(data.expires_at)
    } catch {
      if (!abort.signal.aborted) setError(current
        ? 'Code could not be prepared. Retry for this same Node; any previous unused code will be replaced.'
        : 'Reservation result is unknown. Close and refresh the Node list before trying again.')
    } finally {
      if (!abort.signal.aborted) { setBusy(false); request.current = null }
    }
  }
  const revoke = async () => {
    if (!reserved || request.current) return
    const abort = new AbortController(); request.current = abort; setBusy(true); setError('')
    try {
      await api.post('/foreign-install/revoke', { node_id: reserved.id }, { signal: abort.signal })
      if (!abort.signal.aborted) { setPacket(''); setExpires(0); setCopied(false) }
    } catch { if (!abort.signal.aborted) setError('Revocation could not be confirmed. The code may still be valid.') }
    finally { if (!abort.signal.aborted) { setBusy(false); request.current = null } }
  }
  const copy = async () => {
    if (!packet || expires * 1000 <= Date.now()) return
    try { await navigator.clipboard.writeText(packet); setCopied(true) }
    catch { setError('Clipboard unavailable. Select and copy the installation information manually.') }
  }
  return <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
    <section role="dialog" aria-modal="true" aria-labelledby="foreign-install-title" className="bg-white dark:bg-gray-800 text-gray-900 dark:text-white rounded-xl p-6 max-w-xl w-full max-h-[90vh] overflow-y-auto whitespace-normal">
      <div className="flex justify-between gap-4 mb-4">
        <h2 id="foreign-install-title" className="text-xl font-semibold">Foreign Node installation — Trial</h2>
        <button type="button" aria-label="Close installation dialog" onClick={onClose}>Close</button>
      </div>
      <p className="text-sm mb-4">First verify the Iran Node is Connected in the Panel. Then reserve this Foreign Node with its Gateway domain and copy the installation information for Smite Manager option 2 on the Foreign server. The code expires 2 hours after it is issued—not after installation finishes. Expiry does not disconnect an already enrolled Node. The combined installer is still in trial and is not released yet.</p>
      {!packet ? <form onSubmit={event => { event.preventDefault(); void issue() }}>
        <label className="block mb-3">Node name<input aria-label="Node name" value={name} disabled={!!reserved || busy || uncertain} onChange={e => setName(e.target.value)} autoComplete="off" className="block w-full p-2 border rounded dark:bg-gray-900" /></label>
        <label className="block mb-3">Foreign Gateway domain<input aria-label="Foreign Gateway domain" value={domain} disabled={busy || uncertain} onChange={e => setDomain(e.target.value)} placeholder="kh.your-domain.com" autoComplete="off" spellCheck={false} className="block w-full p-2 border rounded dark:bg-gray-900" /></label>
        <p className="text-sm mb-3">A new code replaces earlier unused codes for this Node. Use the same domain to preserve its Gateway path.</p>
        <button type="submit" disabled={busy || uncertain} className="px-4 py-2 bg-blue-600 text-white rounded disabled:opacity-50">{busy ? 'Preparing…' : 'Prepare installation information'}</button>
      </form> : <div>
        <p className="text-sm mb-2">Copy into your Foreign installer only. This information disappears when the dialog closes.</p>
        <textarea aria-label="One-time installation information" readOnly value={packet} autoComplete="off" spellCheck={false} rows={10} onFocus={e => e.currentTarget.select()} className="w-full font-mono text-xs p-2 border rounded dark:bg-gray-900" />
        <div className="flex flex-wrap gap-3 mt-3">
          <button type="button" onClick={copy} disabled={busy || left <= 0} className="px-3 py-2 bg-blue-600 text-white rounded">{copied ? 'Copied' : 'Copy installation information'}</button>
          <button type="button" onClick={revoke} disabled={busy}>Revoke unused code</button>
        </div>
        <p role="status" className="mt-2">Expires in {Math.ceil(left / 60)} minutes</p>
      </div>}
      {error && <p role="alert" className="mt-3 text-red-600 dark:text-red-300">{error}</p>}
      <p className="text-xs mt-4">Closing does not revoke the code. Clear your clipboard after use. No installation information is saved in browser storage.</p>
    </section>
  </div>
}
