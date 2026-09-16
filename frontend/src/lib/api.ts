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

/** `partial`: finished, but at least one analyzer failed or timed out. Not a clean result. */
export type ScanStatus = 'queued' | 'running' | 'completed' | 'partial' | 'failed'
export const isTerminalStatus = (status: ScanStatus) =>
  status === 'completed' || status === 'partial' || status === 'failed'
/** The scan produced findings to show (possibly incomplete). */
export const hasResults = (status: ScanStatus) => status === 'completed' || status === 'partial'

export type AnalyzerRunStatus = 'running' | 'completed' | 'failed' | 'timed_out' | 'skipped'

export type AnalyzerRun = {
  analyzer: string
  display_name: string
  status: AnalyzerRunStatus
  duration_ms: number | null
  /** Findings the tool reported, before deduplication across analyzers. */
  finding_count: number | null
  error_message: string | null
  /** Non-fatal problems that reduced coverage. */
  warnings: string[]
  started_at: string | null
  completed_at: string | null
}

export type AnalyzerSummary = { total: number; completed: number; failed: number; running: number; skipped: number }

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
  /** Deduplicated findings per analyzer whose report was kept. */
  findings_by_analyzer: Record<string, number>
  findings_before_dedup: number
  analyzer_runs: AnalyzerRun[]
  analyzer_summary: AnalyzerSummary
}

export type ScanCreated = { scan_id: string; status: ScanStatus }

export type DependencyInfo = {
  ecosystem: string
  package: string
  installed_version: string
  advisory_id: string
  aliases: string[]
  fixed_version: string | null
  fixed_versions: string[]
  cvss_score: string | null
}

export type MergedFinding = {
  analyzer: string
  rule_id: string
  severity: Severity
  start_line: number | null
  message: string
}

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
  category: string | null
  /** Other analyzers that reported the same issue. */
  corroborated_by: string[]
  merged_from: MergedFinding[]
  dependency: DependencyInfo | null
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

export type FindingsQuery = {
  severity?: Severity[]
  /** Matches findings reported or corroborated by any of these analyzers. */
  analyzer?: string[]
  filePath?: string
  page?: number
  pageSize?: number
}

export function getFindings(scanId: string, query: FindingsQuery = {}): Promise<FindingPage> {
  return request(() =>
    api.get<FindingPage>(`/scans/${encodeURIComponent(scanId)}/findings`, {
      params: {
        severity: query.severity?.length ? query.severity : undefined,
        analyzer: query.analyzer?.length ? query.analyzer : undefined,
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
