import { useQuery } from '@tanstack/react-query'
import { type ApiError, type AuthConfig, getAuthConfig, getMe, type Me } from '@/lib/api'

export const ME_QUERY_KEY = ['auth', 'me'] as const

/** The signed-in user (null when signed out). Also keeps the CSRF token for mutations. */
export function useMe() {
  return useQuery<Me | null, ApiError>({
    queryKey: ME_QUERY_KEY,
    queryFn: getMe,
    staleTime: 60_000,
    retry: 1,
  })
}

export function useAuthConfig() {
  return useQuery<AuthConfig, ApiError>({
    queryKey: ['auth', 'config'],
    queryFn: getAuthConfig,
    staleTime: Infinity,
  })
}
