/**
 * Read-only validation for ports entered after the 3x-UI inbound exists.
 * Never silently omit malformed values or substitute a default port.
 */
export function parseInboundPorts(raw: string): number[] | null {
  const parts = raw.split(',').map(port => port.trim())
  if (!parts.length || parts.length > 128 || parts.some(part => !/^[0-9]+$/.test(part))) {
    return null
  }
  const ports = parts.map(Number)
  if (
    ports.some(port => !Number.isInteger(port) || port < 1 || port > 65535) ||
    new Set(ports).size !== ports.length
  ) {
    return null
  }
  return ports
}
