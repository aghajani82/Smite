const controlPort = 3080
const bridgePort = 13080
const reservedPorts = new Set([443, 7000, 8000, 8443, 8888, 18476, controlPort, bridgePort])

export function buildManagedBackhaulSpec(input: string, ports: number[]) {
  const [port] = ports
  if (!/^\d{1,5}$/.test(input.trim()) || ports.length !== 1 ||
      Number(input) !== port || port < 1024 || port > 65535 || reservedPorts.has(port)) {
    return null
  }

  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(32))
  return {
    uopti_standard_backhaul: true,
    transport: 'ws',
    token: Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join(''),
    data_port: port,
    control_port: controlPort,
    bridge_port: bridgePort,
    ports: [`127.0.0.1:${port}=127.0.0.1:${port}`],
  }
}
