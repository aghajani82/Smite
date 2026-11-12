export interface InstallNode { id: string; name: string }
export interface InstallationGrant {
  node_id: string; node_name: string; origin: string; control_url: string
  installation_code: string; expires_at: number
}
export const validInstallDomain = (domain: string): boolean =>
  /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain) &&
  !/\.(localhost|local|internal|home|lan|test|invalid|example|onion)$/.test(domain)

/** Validate before displaying or copying a bearer credential. No persistence. */
export function installationPacket(data: InstallationGrant, node: InstallNode, domain: string, panel: string, now = Date.now()) {
  const origin = `https://${domain}:443`
  const panelURL = new URL(panel)
  if (!validInstallDomain(domain) || panelURL.protocol !== 'https:' ||
      (panelURL.port !== '' && panelURL.port !== '443') || panelURL.username || panelURL.password ||
      panelURL.pathname !== '/' || panelURL.search || panelURL.hash ||
      data.node_id !== node.id || data.node_name !== node.name || data.origin !== origin ||
      !data.control_url.startsWith(origin) ||
      !/^\/smite-node\/[0-9a-f]{32}$/.test(data.control_url.slice(origin.length)) ||
      !/^smi1_[A-Za-z0-9_-]{43}$/.test(data.installation_code) ||
      !Number.isInteger(data.expires_at) || data.expires_at * 1000 <= now ||
      data.expires_at * 1000 > now + 7200000) throw new Error('Invalid installation response')
  return JSON.stringify({ protocol: 'smi1', panel_url: panelURL.origin,
    node_id: data.node_id, node_name: data.node_name, origin: data.origin,
    control_url: data.control_url, installation_code: data.installation_code,
    expires_at: data.expires_at }, null, 2)
}
