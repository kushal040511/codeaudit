export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export function formatDateTime(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString() : '—'
}

export function formatDuration(startIso: string | null, endIso: string | null): string | null {
  if (!startIso || !endIso) return null
  const seconds = Math.max(0, Math.round((Date.parse(endIso) - Date.parse(startIso)) / 1000))
  return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`
}

export function formatMilliseconds(ms: number | null): string {
  if (ms === null) return '—'
  if (ms < 1000) return `${ms} ms`
  const seconds = ms / 1000
  return seconds < 60 ? `${seconds.toFixed(1)} s` : `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`
}
