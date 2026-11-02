export interface Status {
  system: {
    cpu_percent: number
    memory_percent: number
    memory_total_gb: number
    memory_used_gb: number
  }
  tunnels: { total: number; active: number }
  nodes: { total: number; active: number }
}


export function validStatus(value: unknown): value is Status {
  if (!value || typeof value !== 'object') return false
  const s = value as Status
  const nonnegative = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v) && v >= 0
  const percentage = (v: unknown) => nonnegative(v) && v <= 100
  const counts = (v: Status['nodes']) => v && Number.isInteger(v.total) && Number.isInteger(v.active) && nonnegative(v.total) && nonnegative(v.active) && v.active <= v.total
  return Boolean(s.system && percentage(s.system.cpu_percent) && percentage(s.system.memory_percent)
    && nonnegative(s.system.memory_total_gb) && nonnegative(s.system.memory_used_gb)
    && s.system.memory_used_gb <= s.system.memory_total_gb && counts(s.nodes) && counts(s.tunnels))
}

export function registeredRoles(value: unknown): { iran: boolean; foreign: boolean } | null {
  if (!Array.isArray(value) || value.some(node => !node || !['iran', 'foreign'].includes(node.metadata?.role))) return null
  return { iran: value.some(node => node.metadata.role === 'iran'), foreign: value.some(node => node.metadata.role === 'foreign') }
}

export function setupCount(registered: { iran: boolean; foreign: boolean } | null, status: Status | null, error: boolean): number | null {
  if (!registered || !status || error) return null
  return Number(registered.iran) + Number(registered.foreign) + Number(status.tunnels.total > 0)
}
