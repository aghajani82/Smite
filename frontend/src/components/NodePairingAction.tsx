import { useEffect, useRef, useState } from 'react'
import { Check, ClipboardCopy, KeyRound, ShieldAlert, X } from 'lucide-react'
import api from '../api/client'

export interface PairableNode {
  id: string
  name: string
}

type Role = 'iran' | 'foreign'

interface PairingCapabilities {
  pairing_preview_enabled: boolean
  legacy_node_auth_enforced: boolean
}

/**
 * Server-side admin JWT and disabled-by-default preview gate are authoritative.
 * A React check is UI only; it is never authentication enforcement.
 */
export const usePairingPreviewAvailability = (): boolean => {
  const [available, setAvailable] = useState(false)

  useEffect(() => {
    const controller = new AbortController()
    api.get<PairingCapabilities>('/node-pairing/capabilities', {
      signal: controller.signal,
      headers: { 'Cache-Control': 'no-store' },
    }).then(({ data }) => {
      setAvailable(data.pairing_preview_enabled === true && data.legacy_node_auth_enforced === false)
    }).catch(() => {
      // Older Panel, missing JWT or disabled preview: fail closed for UI.
      setAvailable(false)
    })
    return () => controller.abort()
  }, [])

  return available
}

interface PairingActionProps {
  node: PairableNode
  role: Role
  enabled: boolean
}

/** Never store the pairing code in URL, localStorage, sessionStorage or logs. */
export const NodePairingAction = ({ node, role, enabled }: PairingActionProps) => {
  const [open, setOpen] = useState(false)
  if (!enabled) return null

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="inline-flex items-center gap-1 mr-3 text-blue-700 dark:text-blue-300 hover:underline"
        aria-label={"Prepare pairing code for " + node.name}
      >
        <KeyRound size={15} /> Pair (preview)
      </button>
      {open && (
        <NodePairingDialog
          key={node.id}
          node={node}
          role={role}
          onClose={() => setOpen(false)}
        />
      )}
    </>
  )
}

interface NodePairingDialogProps {
  node: PairableNode
  role: Role
  onClose: () => void
}

/**
 * The secret exists in component state ONLY while this dialog is mounted.
 * It is automatically removed when the code expires or the dialog closes.
 * This code does NOT secure legacy Node registration or tunnel commands.
 */
const NodePairingDialog = ({ node, role, onClose }: NodePairingDialogProps) => {
  const [verified, setVerified] = useState(false)
  const [pairingCode, setPairingCode] = useState<string | null>(null)
  const [expiresAt, setExpiresAt] = useState<number | null>(null)
  const [secondsLeft, setSecondsLeft] = useState(0)
  const [requesting, setRequesting] = useState(false)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)
  const controller = useRef<AbortController | null>(null)

  useEffect(() => {
    // Abort network requests when the one-time secret view is closed.
    return () => controller.current?.abort()
  }, [])

  useEffect(() => {
    if (expiresAt === null) return
    const tick = () => {
      const left = Math.max(0, Math.ceil((expiresAt * 1000 - Date.now()) / 1000))
      setSecondsLeft(left)
      if (left <= 0) {
        setPairingCode(null)
        setExpiresAt(null)
        setCopied(false)
      }
    }
    tick()
    const interval = window.setInterval(tick, 1000)
    return () => window.clearInterval(interval)
  }, [expiresAt])

  const issueCode = async () => {
    if (!verified || requesting || pairingCode) return
    const abort = new AbortController()
    controller.current = abort
    setRequesting(true)
    setError('')
    try {
      const { data } = await api.post<{
        node_id: string
        pairing_code: string
        expires_at: number
      }>('/node-pairing/issue', {
        node_id: node.id,
        role,
        ttl_seconds: 600,
      }, {
        signal: abort.signal,
        headers: { 'Cache-Control': 'no-store' },
      })

      // The response is never added to logs or persistent browser storage.
      if (
        data.node_id !== node.id ||
        !/^smn1_[A-Za-z0-9_-]{32,100}$/.test(data.pairing_code) ||
        !Number.isInteger(data.expires_at) ||
        data.expires_at * 1000 <= Date.now()
      ) {
        throw new Error('Invalid pairing response')
      }
      setPairingCode(data.pairing_code)
      setExpiresAt(data.expires_at)
    } catch {
      if (!abort.signal.aborted) {
        // Do not dump error.response/data: could leak credentials.
        setError('Pairing could not be prepared. Verify Panel readiness and your session.')
      }
    } finally {
      setRequesting(false)
      controller.current = null
    }
  }

  const copyCode = async () => {
    if (!pairingCode || secondsLeft <= 0) return
    try {
      await navigator.clipboard.writeText(pairingCode)
      setCopied(true)
    } catch {
      setError('Clipboard access was denied. Select and copy the code manually.')
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose()
      }}
    >
      <div role="dialog" aria-modal="true" aria-labelledby="node-pairing-title" className="bg-white dark:bg-gray-800 rounded-xl p-6 max-w-xl w-full max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between gap-3 mb-3">
          <h2 id="node-pairing-title" className="text-xl font-semibold text-gray-900 dark:text-white">
            Secure Node Pairing — Preview
          </h2>
          <button type="button" aria-label="Close pairing dialog" onClick={onClose} className="text-gray-500 dark:text-gray-300">
            <X size={22} />
          </button>
        </div>

        <div className="flex items-start gap-2 p-3 mb-4 rounded-md border border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-950/40 text-amber-900 dark:text-amber-100 text-sm">
          <ShieldAlert size={20} className="shrink-0" />
          <p>
            This is a staged enrollment preview. It does not secure the existing
            Node API or activate signed Panel ↔ Node tunnel commands.
            Do not use until the HTTPS/443 gateway and U-OPTI rollout are verified.
          </p>
        </div>

        <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-2 text-sm mb-4 text-gray-700 dark:text-gray-200">
          <dt>Name</dt><dd className="font-semibold">{node.name}</dd>
          <dt>Role</dt><dd>{role}</dd>
          <dt>Node UUID</dt><dd className="break-all font-mono select-all">{node.id}</dd>
          <dt>Valid for</dt><dd>10 minutes (one use)</dd>
        </dl>

        {!pairingCode ? (
          <>
            <label className="flex items-start gap-2 text-sm text-gray-700 dark:text-gray-200 mb-4 cursor-pointer">
              <input type="checkbox" checked={verified}
                onChange={(event) => setVerified(event.target.checked)}
                className="mt-1" />
              I verified the Node identity, role and host using a trusted channel.
            </label>
            {error && <p role="alert" className="mb-3 text-sm text-red-600 dark:text-red-300">{error}</p>}
            <button type="button" onClick={issueCode} disabled={!verified || requesting}
              className="px-4 py-2 rounded-md bg-blue-600 text-white disabled:opacity-50">
              {requesting ? 'Preparing…' : 'Generate one-time pairing code'}
            </button>
          </>
        ) : (
          <section aria-label="One-time pairing code">
            <p className="text-sm text-red-700 dark:text-red-300 mb-2">
              This code is sensitive. Transfer it only to your own Node wizard.
              It will disappear here when you close this dialog or it expires.
            </p>
            <input
              aria-label="One-time pairing code"
              readOnly
              value={pairingCode}
              autoComplete="off"
              spellCheck={false}
              className="w-full font-mono text-sm border rounded-md p-2 bg-gray-100 dark:bg-gray-900 dark:text-white"
              onFocus={(event) => event.currentTarget.select()}
            />
            <div className="flex items-center gap-3 mt-3">
              <button type="button" onClick={copyCode} disabled={secondsLeft <= 0}
                className="inline-flex items-center gap-2 px-3 py-2 rounded-md bg-blue-600 text-white">
                {copied ? <Check size={16} /> : <ClipboardCopy size={16} />}
                {copied ? 'Copied' : 'Copy once'}
              </button>
              <span className="text-sm text-gray-600 dark:text-gray-300" role="status">
                Expires in {secondsLeft}s
              </span>
            </div>
            {error && <p role="alert" className="mt-3 text-sm text-red-600 dark:text-red-300">{error}</p>}
          </section>
        )}
        <p className="mt-4 text-xs text-gray-500 dark:text-gray-400">
          Copying to the system clipboard may leave a copy outside Smite.
          Clear your clipboard after use. Only the Node credential wizard should redeem this code.
        </p>
      </div>
    </div>
  )
}
