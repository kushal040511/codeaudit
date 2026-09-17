import type { QuotaLimit } from '@/lib/api'
import { formatReset, useQuotas } from '@/lib/quotas'

/** "7 of 10 scans left today", or when the next one frees up once none are left. */
export function QuotaHint({ name }: { name: QuotaLimit['name'] }) {
  const quotas = useQuotas()
  const limit = quotas.data?.limits.find((item) => item.name === name)
  if (!limit || limit.limit === 0) return null
  const noun = limit.description.replace(/ per (day|hour|minute)$/, '')
  if (limit.remaining === 0) {
    return (
      <p className="text-xs text-destructive" role="status">
        No {noun} left. The next one frees up {formatReset(limit.reset_seconds)}.
        {quotas.data?.tier === 'anonymous' && ' Sign in for higher limits.'}
      </p>
    )
  }
  return (
    <p className="text-xs text-muted-foreground">
      {limit.remaining} of {limit.limit} {noun} left {limit.window_seconds === 86_400 ? 'today' : 'this hour'}.
    </p>
  )
}
