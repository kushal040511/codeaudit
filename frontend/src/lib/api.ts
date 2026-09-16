import axios from 'axios'

const API_ORIGIN = import.meta.env.VITE_API_ORIGIN ?? ''

/** Client for API routes (/api/...). Arrays serialize as repeated keys: severity=a&severity=b. */
export const api = axios.create({
  baseURL: `${API_ORIGIN}/api`,
  timeout: 30_000,
  paramsSerializer: { indexes: null },
})

// ---------- Types (mirror backend/app/schemas) ----------

export type Severity = 'info' | 'warning' | 'error' | 'critical'
/** Most severe first. */
export const SEVERITIES: readonly Severity[] = ['critical', 'error', 'warning', 'info']

export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed'
export const isTerminalStatus = (status: ScanStatus) => status === 'completed' || status === 'failed'

export type DetectedLanguage = { language: string; file_count: number; manifests: string[] }
export type SeverityCounts = Record<Severity, number>

export type Scan = {
  id: string
  status: ScanStatus
  original_filename: string
  detected_languages: DetectedLanguage[] | null
  error_message: string | null
  created_at: string
  started_at: string | null
  completed_at: string | null
  finding_counts: SeverityCounts
  total_findings: number
}

export type ScanCreated = { scan_id: string; status: ScanStatus }

export type Finding = {
  id: number
  analyzer: string
  rule_id: string
  severity: Severity
  file_path: string
  start_line: number
  end_line: number
  message: string
  code_snippet: string | null
}

export type FindingPage = { items: Finding[]; total: number; page: number; page_size: number }

export type ComponentCheck = { status: 'ok' | 'error'; latency_ms: number | null; detail: string | null }
export type HealthResponse = {
  status: 'ok' | 'unavailable'
  version: string
  checks: Record<string, ComponentCheck>
}

// ---------- Errors ----------

type ApiErrorBody = { error?: { code: string; message: string; details?: unknown } }

export class ApiError extends Error {
  readonly status: number | undefined
  readonly code: string | undefined

  constructor(message: string, status?: number, code?: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

export function toApiError(err: unknown): ApiError {
  if (err instanceof ApiError) return err
  if (axios.isAxiosError<ApiErrorBody>(err)) {
    const status = err.response?.status
    const body = err.response?.data?.error
    if (body) return new ApiError(body.message, status, body.code)
    if (status) return new ApiError(`Request failed with status ${status}.`, status)
    return new ApiError('Could not reach the CodeAudit API.')
  }
  return new ApiError(err instanceof Error ? err.message : 'Unexpected error.')
}

async function request<T>(fn: () => Promise<{ data: T }>): Promise<T> {
  try {
    return (await fn()).data
  } catch (err) {
    throw toApiError(err)
  }
}

// ---------- Endpoints ----------

export function uploadScan(file: File, onProgress?: (fraction: number) => void): Promise<ScanCreated> {
  const form = new FormData()
  form.append('file', file)
  return request(() =>
    api.post<ScanCreated>('/scans', form, {
      timeout: 0, // large uploads on slow links
      onUploadProgress: (event) => {
        if (event.total) onProgress?.(event.loaded / event.total)
      },
    }),
  )
}

export function getScan(scanId: string): Promise<Scan> {
  return request(() => api.get<Scan>(`/scans/${encodeURIComponent(scanId)}`))
}

export type FindingsQuery = { severity?: Severity[]; filePath?: string; page?: number; pageSize?: number }

export function getFindings(scanId: string, query: FindingsQuery = {}): Promise<FindingPage> {
  return request(() =>
    api.get<FindingPage>(`/scans/${encodeURIComponent(scanId)}/findings`, {
      params: {
        severity: query.severity?.length ? query.severity : undefined,
        file_path: query.filePath || undefined,
        page: query.page,
        page_size: query.pageSize,
      },
    }),
  )
}

/** /health lives at the backend root. A 503 still carries a valid body. */
export function getHealth(): Promise<HealthResponse> {
  return request(() =>
    axios.get<HealthResponse>(`${API_ORIGIN}/health`, {
      timeout: 10_000,
      validateStatus: (status) => status === 200 || status === 503,
    }),
  )
}
