export interface InstallNode { id: string; name: string }
export interface InstallationGrant {
  node_id: string; node_name: string; origin: string; control_url: string
  installation_code: string; expires_at: number
}
export const validInstallDomain = (domain: string): boolean =>
  /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain) &&
  !/\.(localhost|local|internal|home|lan|test|invalid|example|onion)$/.test(domain)

/** The server enforces the actual two-hour grant lifetime. The browser clock is
 * not an authority for grant expiry: it may differ from the Panel host clock. */
export function installationLifetimeSeconds(expiresAt: number, serverDate: unknown): number {
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= 0) throw new Error('Invalid installation response')
  const serverNow = typeof serverDate === 'string' ? Date.parse(serverDate) : NaN
  // A same-origin HTTP Date header follows server time, not the operator's PC.
  // If the proxy omits it, start a conservative local display countdown.
  // The Panel still rejects expired or replayed codes on redemption.
  if (!Number.isFinite(serverNow)) return 7195
  const remaining = expiresAt - Math.floor(serverNow / 1000)
  if (remaining <= 0 || remaining > 7200 + 300) throw new Error('Invalid installation response')
  return Math.min(remaining, 7200)
}

/** Validate identity, origin and credential format before showing the secret. */
export function installationPacket(data: InstallationGrant, node: InstallNode, domain: string, panel: string) {
  const origin = `https://${domain}:443`
  const panelURL = new URL(panel)
  if (!validInstallDomain(domain) || panelURL.protocol !== 'https:' ||
      (panelURL.port !== '' && panelURL.port !== '443') || panelURL.username || panelURL.password ||
      panelURL.pathname !== '/' || panelURL.search || panelURL.hash ||
      data.node_id !== node.id || data.node_name !== node.name || data.origin !== origin ||
      !data.control_url.startsWith(origin) ||
      !/^\/smite-node\/[0-9a-f]{32}$/.test(data.control_url.slice(origin.length)) ||
      !/^smi1_[A-Za-z0-9_-]{43}$/.test(data.installation_code) ||
      !Number.isSafeInteger(data.expires_at) || data.expires_at <= 0) throw new Error('Invalid installation response')
  return JSON.stringify({ protocol: 'smi1', panel_url: panelURL.origin,
    node_id: data.node_id, node_name: data.node_name, origin: data.origin,
    control_url: data.control_url, installation_code: data.installation_code,
    expires_at: data.expires_at }, null, 2)
}
