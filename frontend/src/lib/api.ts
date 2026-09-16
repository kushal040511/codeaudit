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

/**
 * `analysis_complete` / `enriching`: findings are ready, LLM suggestions are still coming.
 * `partial`: finished, but at least one analyzer failed or timed out. Not a clean result.
 */
export type ScanStatus = 'queued' | 'running' | 'analysis_complete' | 'enriching' | 'completed' | 'partial' | 'failed'
export const isTerminalStatus = (status: ScanStatus) =>
  status === 'completed' || status === 'partial' || status === 'failed'
/** The scan produced findings to show (possibly incomplete, possibly still being enriched). */
export const hasResults = (status: ScanStatus) =>
  status === 'analysis_complete' || status === 'enriching' || status === 'completed' || status === 'partial'

export type EnrichmentStatus = 'pending' | 'running' | 'completed' | 'partial' | 'failed' | 'skipped'

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
  enrichment_status: EnrichmentStatus | null
  enrichment_error: string | null
  llm_usage: LlmUsageSummary
}

export type LlmUsageSummary = {
  tokens: number
  cost_usd: number
  calls: number
  fix_suggestions: number
  valid_fix_suggestions: number
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
  fix_status: FixStatus | null
  fix_validation_status: ValidationStatus | null
}

// ---------- LLM enrichment ----------

export type FixStatus = 'generating' | 'ready' | 'failed'
export type ValidationStatus = 'valid' | 'failed_to_apply' | 'syntax_error' | 'no_patch' | 'not_validated'

export type FileChange = { path: string; start_line: number; original: string; patched: string }

export type FixSuggestion = {
  finding_id: number
  status: FixStatus
  validation_status: ValidationStatus
  /** True only if the patch applies cleanly to the scanned code and the result parses. */
  patch_verified: boolean
  validation_detail: string | null
  explanation: string | null
  confidence: 'high' | 'medium' | 'low' | null
  /** Present only when verified. */
  patch: string | null
  /** The unverified patch, for transparency. Never offer it as a fix. */
  rejected_patch: string | null
  breaking_risk: 'none' | 'low' | 'high' | null
  test_suggestion: string | null
  file_changes: FileChange[]
  shared_with_finding_ids: number[]
  user_hint: string | null
  version: number
  model: string | null
  error_message: string | null
  updated_at: string
}

export type ReviewIssue = {
  title: string
  severity: string
  evidence: string[]
  why_it_matters: string
  refactor_steps: string[]
  rejected_evidence: { evidence: string; reason: string }[]
  unverified_mentions: string[]
}

export type ArchitectureReview = {
  status: 'ready' | 'failed'
  summary: string | null
  strengths: string[]
  issues: ReviewIssue[]
  dropped_issues: ReviewIssue[]
  suggested_target_structure: string | null
  citations_total: number
  citations_invalid: number
  hallucination_rate: number | null
  model: string | null
  error_message: string | null
  created_at: string
}

export type LlmPurpose = 'fix_suggestion' | 'fix_regeneration' | 'architecture_review'

export type LlmUsage = {
  enrichment_status: EnrichmentStatus | null
  enrichment_error: string | null
  model: string | null
  token_budget: number
  tokens_used: number
  input_tokens: number
  output_tokens: number
  cost_usd: number
  calls: number
  failed_calls: number
  total_duration_ms: number
  pricing_note: string
  by_purpose: { purpose: LlmPurpose; calls: number; failed_calls: number; input_tokens: number; output_tokens: number; cost_usd: number }[]
}

export type FindingPage = { items: Finding[]; total: number; page: number; page_size: number }

// ---------- Architecture ----------

export type ArchitectureIssueType = 'circular_dependency' | 'layer_violation' | 'god_module' | 'orphan_module'
export type EdgeKind = 'internal' | 'external' | 'unresolved'

export type GraphNode = {
  /** Module id, or "dir:<path>" for an aggregated directory. */
  id: string
  kind: 'module' | 'directory'
  label: string
  path: string
  module_count: number
  loc: number
  definition_count: number
  fan_in: number
  fan_out: number
  instability: number | null
  centrality: number
  layer: string | null
  language: string | null
  is_entrypoint: boolean
  is_test: boolean
  parse_error_count: number
  issue_ids: number[]
}

export type GraphEdge = {
  id: string
  source: string
  target: string
  module_edge_count: number
  import_count: number
  type_only: boolean
  lazy: boolean
  in_cycle: boolean
  layer_violation: boolean
  issue_ids: number[]
}

export type GraphIssueRef = {
  id: number
  issue_type: ArchitectureIssueType
  severity: Severity
  title: string
  node_ids: string[]
  edge_ids: string[]
}

export type ExternalDependency = {
  name: string
  language: string
  importer_count: number
  import_count: number
  evidence: string | null
}

export type ResolutionSummary = {
  total: number
  internal: number
  external: number
  asset: number
  unresolved: number
  undeclared_external: number
  coverage: number
  unresolved_by_reason: Record<string, number>
  unresolved_by_form: Record<string, number>
}

export type ArchitectureSummary = {
  node_count: number
  edge_count: number
  type_only_edge_count: number
  density: number
  average_degree: number
  max_depth: number
  cycle_count: number
  cycles_truncated: boolean
  cyclic_module_count: number
  layer_violation_count: number
  god_module_count: number
  orphan_count: number
  total_loc: number
  languages: Record<string, number>
  layers: Record<string, number>
  parse: { files: number; parsed: number; skipped: number; skipped_files: { path: string; reason: string }[] }
  resolution: ResolutionSummary
  timings: Record<string, number>
}

export type ArchitectureGraph = {
  summary: ArchitectureSummary
  view: {
    total_modules: number
    aggregated: boolean
    depth: number | null
    max_nodes: number
    expanded: string[]
    collapsed: string[]
  }
  nodes: GraphNode[]
  edges: GraphEdge[]
  issues: GraphIssueRef[]
  external_dependencies: ExternalDependency[]
}

export type ArchitectureIssue = {
  id: number
  issue_type: ArchitectureIssueType
  severity: Severity
  title: string
  description: string
  /** involved_modules[0] is the primary module. */
  involved_modules: string[]
  involved_edges: [string, string][]
  metric_value: number | null
  details: Record<string, unknown>
}

export type ModuleImport = {
  module: string
  path: string | null
  kind: EdgeKind
  import_statement: string
  line: number
  import_count: number
  type_only: boolean
  lazy: boolean
  resolution: string | null
}

export type ModuleDetail = {
  module_id: string
  path: string
  language: string
  loc: number
  definition_count: number
  fan_in: number
  fan_out: number
  instability: number | null
  centrality: number
  layer: string | null
  layer_stack: string | null
  is_entrypoint: boolean
  is_test: boolean
  parse_error: string | null
  symbols: string[]
  importers: ModuleImport[]
  imports: ModuleImport[]
  issues: ArchitectureIssue[]
}

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

export function getFix(scanId: string, findingId: number): Promise<FixSuggestion> {
  return request(() => api.get<FixSuggestion>(`/scans/${encodeURIComponent(scanId)}/findings/${findingId}/fix`))
}

export function regenerateFix(scanId: string, findingId: number, hint?: string): Promise<FixSuggestion> {
  return request(() =>
    api.post<FixSuggestion>(`/scans/${encodeURIComponent(scanId)}/findings/${findingId}/fix/regenerate`, {
      hint: hint?.trim() || null,
    }),
  )
}

export function getArchitectureReview(scanId: string): Promise<ArchitectureReview> {
  return request(() => api.get<ArchitectureReview>(`/scans/${encodeURIComponent(scanId)}/architecture-review`))
}

export function getLlmUsage(scanId: string): Promise<LlmUsage> {
  return request(() => api.get<LlmUsage>(`/scans/${encodeURIComponent(scanId)}/llm-usage`))
}

export type GraphQuery = { maxNodes?: number; expand?: string[]; collapse?: string[] }

export function getArchitectureGraph(scanId: string, query: GraphQuery = {}): Promise<ArchitectureGraph> {
  return request(() =>
    api.get<ArchitectureGraph>(`/scans/${encodeURIComponent(scanId)}/graph`, {
      params: {
        max_nodes: query.maxNodes,
        expand: query.expand?.length ? query.expand : undefined,
        collapse: query.collapse?.length ? query.collapse : undefined,
      },
    }),
  )
}

export function getGraphModule(scanId: string, moduleId: string): Promise<ModuleDetail> {
  return request(() =>
    api.get<ModuleDetail>(`/scans/${encodeURIComponent(scanId)}/graph/module`, { params: { module_id: moduleId } }),
  )
}

export function getArchitectureIssues(scanId: string): Promise<ArchitectureIssue[]> {
  return request(() => api.get<ArchitectureIssue[]>(`/scans/${encodeURIComponent(scanId)}/architecture-issues`))
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
