import { useQuery } from '@tanstack/react-query'
import { type ApiError, getQuotas, type QuotaStatus } from '@/lib/api'

export const QUOTAS_QUERY_KEY = ['quotas'] as const

export function useQuotas() {
  return useQuery<QuotaStatus, ApiError>({
    queryKey: QUOTAS_QUERY_KEY,
    queryFn: getQuotas,
    staleTime: 15_000,
    retry: false,
  })
}

export function formatReset(seconds: number): string {
  if (seconds <= 0) return 'now'
  if (seconds < 90) return `in ${seconds}s`
  if (seconds < 5400) return `in ${Math.round(seconds / 60)} min`
  return `in ${Math.round(seconds / 3600)} h`
}

