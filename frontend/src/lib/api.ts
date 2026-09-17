import axios from 'axios'

const API_ORIGIN = import.meta.env.VITE_API_ORIGIN ?? ''

/** Client for API routes (/api/...). Arrays serialize as repeated keys: severity=a&severity=b. */
export const api = axios.create({
  baseURL: `${API_ORIGIN}/api`,
  timeout: 30_000,
  paramsSerializer: { indexes: null },
  // The session is an HttpOnly cookie; needed when the API is on another origin.
  withCredentials: true,
})

// State-changing requests authenticated by the session cookie must echo the CSRF token.
let csrfToken: string | null = null
export function setCsrfToken(token: string | null) {
  csrfToken = token
}
api.interceptors.request.use((config) => {
  const method = (config.method ?? 'get').toLowerCase()
  if (csrfToken && !['get', 'head', 'options'].includes(method)) {
    config.headers.set('X-CSRF-Token', csrfToken)
  }
  return config
})

/** Browser navigation (not XHR): GitHub redirects back to the API, which redirects to `next`. */
export function githubLoginUrl({ privateRepos = false, next = '/settings' } = {}): string {
  const params = new URLSearchParams({ next })
  if (privateRepos) params.set('private', 'true')
  return `${API_ORIGIN}/api/auth/github/login?${params}`
}

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

export type ScanSource = 'upload' | 'github'

export type RepositoryInfo = {
  owner: string
  name: string
  full_name: string
  /** Branch, tag or commit as requested. */
  ref: string | null
  default_branch: string | null
  commit_sha: string
  private: boolean | null
  html_url: string
}

export type Scan = {
  id: string
  status: ScanStatus
  source: ScanSource
  repository: RepositoryInfo | null
  owned_by_you: boolean
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
  score: ScoreSummary | null
}

export type ScoreSummary = { overall: number | null; grade: string | null; incomplete: boolean; rubric_version: string }

export type CategoryScore = {
  category: 'security' | 'dependencies' | 'architecture' | 'code_health'
  label: string
  /** null: excluded (not applicable, or its analyzer failed). */
  score: number | null
  weight: number
  penalty: number
  finding_count: number
  excluded_reason: string | null
  rationale: string[]
}

export type ScanScore = {
  rubric_version: string
  overall: number | null
  grade: string | null
  incomplete: boolean
  incomplete_reasons: string[]
  categories: CategoryScore[]
  source_loc: number
  module_count: number
  computed_at: string
}

export type ScoreProjection = {
  current: { overall: number | null; grade: string | null; categories: CategoryScore[] }
  projected: { overall: number | null; grade: string | null; categories: CategoryScore[] }
  delta: number | null
  included_finding_ids: number[]
  ignored_finding_ids: number[]
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
  /** Overall score points gained if this finding alone were fixed. */
  score_impact: number | null
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

// ---------- Auth & GitHub ----------

export type GitHubConnection = {
  login: string
  connected: boolean
  scopes: string[]
  private_repo_access: boolean
  token_expires_at: string | null
}

export type Me = {
  id: string
  display_name: string
  avatar_url: string | null
  github: GitHubConnection | null
  csrf_token: string | null
  auth_method: 'session' | 'api_token'
}

export type AuthConfig = { github_enabled: boolean }

export type ApiToken = {
  id: number
  name: string
  prefix: string
  created_at: string
  last_used_at: string | null
  revoked_at: string | null
}
export type ApiTokenCreated = ApiToken & { token: string }

export type GitHubRepo = {
  full_name: string
  private: boolean
  default_branch: string
  description: string | null
  pushed_at: string | null
  html_url: string
}

// ---------- Fix pull requests ----------

export type FixCandidate = {
  suggestion_id: number
  finding_id: number
  severity: Severity
  analyzer: string
  rule_id: string
  file_path: string
  start_line: number
  message: string
  explanation: string | null
  confidence: string | null
  breaking_risk: string | null
  score_impact: number | null
  /** Other findings fixed by the same patch: selected together. */
  shared_with_finding_ids: number[]
  patch: string
}

export type PullRequestStatus = 'previewed' | 'creating' | 'open' | 'failed'

export type PullRequest = {
  id: number
  scan_id: string
  status: PullRequestStatus
  repo_full_name: string
  head_repo_full_name: string
  base_branch: string
  base_sha: string
  branch: string
  use_fork: boolean
  title: string
  body: string
  included_suggestion_ids: number[]
  commits: { sha: string; message: string; suggestion_ids: number[] }[]
  pr_number: number | null
  pr_url: string | null
  error_code: string | null
  error_message: string | null
  created_at: string
  updated_at: string
  confirmed_at: string | null
}

export type PatchCheck = {
  suggestion_ids: number[]
  paths: string[]
  status: 'applies' | 'no_longer_applies' | 'conflicts' | 'syntax_error'
  detail: string | null
}

export type PullRequestPreview = PullRequest & {
  scanned_sha: string
  head_moved: boolean
  can_push: boolean
  requires_fork: boolean
  branch_available: boolean
  suggested_branch: string | null
  combined_diff: string
  files: { path: string; original: string; patched: string }[]
  planned_commits: { message: string; suggestion_ids: number[]; paths: string[] }[]
  patch_checks: PatchCheck[]
  excluded: { suggestion_id: number; reason: string }[]
  blocking: { code: string; message: string }[]
  score: {
    current: number | null
    current_grade: string | null
    projected: number | null
    projected_grade: string | null
    delta: number | null
    rubric_version: string
    incomplete: boolean
  }
  /** Confirming writes a branch, commits and a pull request here. */
  writes_to: string
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

export function getScore(scanId: string): Promise<ScanScore> {
  return request(() => api.get<ScanScore>(`/scans/${encodeURIComponent(scanId)}/score`))
}

export function projectScore(scanId: string, findingIds: number[]): Promise<ScoreProjection> {
  return request(() =>
    api.post<ScoreProjection>(`/scans/${encodeURIComponent(scanId)}/score/projection`, { finding_ids: findingIds }),
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

// ---------- Auth & GitHub endpoints ----------

export function getAuthConfig(): Promise<AuthConfig> {
  return request(() => api.get<AuthConfig>('/auth/config'))
}

/** The signed-in user, or null when signed out. */
export async function getMe(): Promise<Me | null> {
  try {
    const me = await request(() => api.get<Me>('/auth/me'))
    setCsrfToken(me.csrf_token)
    return me
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      setCsrfToken(null)
      return null
    }
    throw err
  }
}

export function logout(): Promise<void> {
  return request(() => api.post<void>('/auth/logout'))
}

export function disconnectGitHub(): Promise<{ disconnected: boolean; revoked_at_github: boolean }> {
  return request(() => api.delete('/auth/github'))
}

export function listGitHubRepos(page = 1): Promise<GitHubRepo[]> {
  return request(() => api.get<GitHubRepo[]>('/auth/github/repos', { params: { page } }))
}

export function listApiTokens(): Promise<ApiToken[]> {
  return request(() => api.get<ApiToken[]>('/auth/tokens'))
}

export function createApiToken(name: string): Promise<ApiTokenCreated> {
  return request(() => api.post<ApiTokenCreated>('/auth/tokens', { name }))
}

export function revokeApiToken(id: number): Promise<void> {
  return request(() => api.delete<void>(`/auth/tokens/${id}`))
}

export function createRepoScan(repoUrl: string, ref?: string): Promise<ScanCreated> {
  return request(() => api.post<ScanCreated>('/scans', { repo_url: repoUrl, ref: ref || null }))
}

// ---------- Fix pull request endpoints ----------

export function getFixCandidates(scanId: string): Promise<FixCandidate[]> {
  return request(() => api.get<FixCandidate[]>(`/scans/${encodeURIComponent(scanId)}/fixes`))
}

export function previewPullRequest(
  scanId: string,
  body: { suggestion_ids: number[]; branch?: string; use_fork?: boolean },
): Promise<PullRequestPreview> {
  return request(() =>
    api.post<PullRequestPreview>(`/scans/${encodeURIComponent(scanId)}/pull-requests/preview`, body, {
      timeout: 120_000,
    }),
  )
}

/** Writes to GitHub. Only call from an explicit user confirmation. */
export function confirmPullRequest(prId: number, edits: { title: string; body: string }): Promise<PullRequest> {
  return request(() => api.post<PullRequest>(`/pull-requests/${prId}/confirm`, { confirm: true, ...edits }))
}

export function listPullRequests(scanId: string): Promise<PullRequest[]> {
  return request(() => api.get<PullRequest[]>(`/scans/${encodeURIComponent(scanId)}/pull-requests`))
}

// ---------- Site analyzer ----------

export type SiteAnalysisStatus = 'queued' | 'running' | 'completed' | 'failed'
export type RiskLevel = 'low' | 'moderate' | 'high' | 'very_high'
export type EvidenceCategory = 'domain' | 'certificate' | 'visual' | 'content' | 'reputation'

export type Evidence = {
  signal: string
  category: EvidenceCategory
  /** Human-readable finding, e.g. "Domain registered 3 days ago". Untrusted page text may appear inside. */
  label: string
  /** Contribution to the risk score (negative = evidence of legitimacy). */
  points: number
  status: 'fired' | 'clear' | 'unavailable' | 'info'
  value: unknown
}

export type VisualMatch = {
  brand: string
  brand_name: string
  page: string
  similarity: number
  reference_url: string
  reference_screenshot_url: string | null
}

export type SiteRisk = {
  score: number
  level: RiskLevel
  summary: string
  evidence: Evidence[]
  impersonated_brand: string | null
  visual_match: VisualMatch | null
  model_version: string
  disclaimer: string
}

export type ColorRole = { hex: string; usage: number; contrast_on_background?: number }
export type DesignTokens = {
  version: number
  source_url: string
  elements_sampled: number
  colors: {
    roles: Partial<Record<'background' | 'surface' | 'text' | 'text_muted' | 'primary' | 'secondary' | 'accent' | 'border', ColorRole>>
    palette: { hex: string; usage: number; background_usage: number; text_usage: number; shades: string[] }[]
  }
  typography: {
    families: {
      body: { name: string; stack: string } | null
      heading: { name: string; stack: string } | null
      all: { name: string; usage: number }[]
    }
    base_size_px: number | null
    sizes: { px: number; rem: number; usage: number; line_height: string | null }[]
    weights: { value: string; usage: number }[]
  }
  spacing: { base_px: number | null; coverage: number; scale: number[]; values: { px: number; usage: number }[] }
  radii: { value: string; usage: number }[]
  shadows: { value: string; usage: number }[]
  vision: {
    layout: string
    visual_hierarchy: string
    style: string
    mood_keywords: string[]
    components: string[]
    imagery: string
    colors: { role: string; claimed_hex: string; hex: string; where: string; distance: number }[]
  } | null
  dropped_colors: { hex: string; role: string; reason: string; nearest_observed?: string | null }[]
  prompt: string
}

export type SiteCapture = {
  title: string
  status: number | null
  redirect_chain: { url: string; status: number | null }[]
  meta: { name: string; content: string }[]
  link_domains: [string, number][]
  forms: { action: string; method: string; input_types: string[]; has_password: boolean; has_card_fields: boolean }[]
  tls: Record<string, unknown> | null
  favicon_url: string | null
  blocked_requests: { url: string; reason: string }[]
  errors: string[]
  duration_ms: number | null
}

export type SiteAnalysis = {
  id: string
  status: SiteAnalysisStatus
  stage: 'capturing' | 'assessing_risk' | 'extracting_design' | null
  url: string
  normalized_url: string
  final_url: string | null
  error_message: string | null
  cached_from_id: string | null
  owned_by_you: boolean
  created_at: string
  started_at: string | null
  completed_at: string | null
  screenshot_url: string | null
  full_screenshot_url: string | null
  capture: SiteCapture | null
  risk: SiteRisk | null
  design: { tokens: DesignTokens; notes: string[] } | null
}

export type SiteAnalysisListItem = {
  id: string
  status: SiteAnalysisStatus
  url: string
  final_url: string | null
  risk_score: number | null
  risk_level: RiskLevel | null
  created_at: string
}

export type SiteAnalyzeCreated = { analysis_id: string; status: SiteAnalysisStatus; normalized_url: string; cached: boolean }
export type TokenFormat = 'json' | 'tailwind' | 'css'

/** Same-origin API paths returned by the backend (e.g. screenshot URLs). */
export function apiAsset(path: string): string {
  return `${API_ORIGIN}${path}`
}

export function analyzeSite(url: string, force = false): Promise<SiteAnalyzeCreated> {
  return request(() => api.post<SiteAnalyzeCreated>('/sites/analyze', { url, force }))
}

export function getSiteAnalysis(id: string): Promise<SiteAnalysis> {
  return request(() => api.get<SiteAnalysis>(`/sites/${encodeURIComponent(id)}`))
}

export function listSiteAnalyses(): Promise<SiteAnalysisListItem[]> {
  return request(() => api.get<SiteAnalysisListItem[]>('/sites'))
}

export function getSiteTokens(id: string, format: TokenFormat): Promise<string> {
  return request(() =>
    api.get<string>(`/sites/${encodeURIComponent(id)}/tokens`, {
      params: { format },
      responseType: 'text',
      transformResponse: (data) => data,
    }),
  )
}
