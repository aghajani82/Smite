/** Shared FRPS children are immutable except for their display name.
 *
 * Never synthesize a child spec from the generic owner Edit form. The RC5
 * Panel API itself rejects child spec changes with 409 (defense in depth).
 */
export function isSharedFrpsChild(core: string, spec: Record<string, unknown> | null | undefined): boolean {
  return core === 'frp'
    && typeof spec?.shared_frps_owner === 'string'
    && spec.shared_frps_owner.length > 0
}

export function sharedChildRenamePayload(name: string): { name: string } {
  const safeName = name.trim()
  if (!safeName) throw new Error('Shared FRPS child name required')
  return { name: safeName }
}
