import { useQuery } from '@tanstack/react-query'
import { LoaderCircle, Sparkles } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { type ApiError, getLlmUsage, type LlmUsage, type Scan } from '@/lib/api'

const STATUS_TEXT: Record<NonNullable<Scan['enrichment_status']>, string> = {
  pending: 'Queued',
  running: 'Generating fix suggestions and an architecture review…',
  completed: 'Complete',
  partial: 'Partly complete',
  failed: 'Failed',
  skipped: 'Skipped',
}

const PURPOSE_LABEL = {
  fix_suggestion: 'Fix suggestions',
  fix_regeneration: 'Regenerated fixes',
  architecture_review: 'Architecture review',
} as const

const usd = (value: number) => `$${value < 0.01 && value > 0 ? value.toFixed(4) : value.toFixed(2)}`

/** LLM stage status plus tokens and cost for this scan. */
export function EnrichmentCard({ scan }: { scan: Scan }) {
  const running = scan.enrichment_status === 'running' || scan.enrichment_status === 'pending'
  const usage = useQuery<LlmUsage, ApiError>({
    queryKey: ['scan', scan.id, 'llm-usage', scan.llm_usage.calls, scan.enrichment_status],
    queryFn: () => getLlmUsage(scan.id),
    enabled: scan.enrichment_status !== null,
  })
  if (scan.enrichment_status === null) return null

  const data = usage.data
  const budgetShare = data ? Math.min(1, data.tokens_used / data.token_budget) : 0
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Sparkles className="size-4 text-violet-600" /> AI suggestions
        </CardTitle>
        <CardDescription className="flex items-center gap-1.5">
          {running && <LoaderCircle className="size-3.5 animate-spin" />}
          {STATUS_TEXT[scan.enrichment_status]}
          {scan.enrichment_error ? ` · ${scan.enrichment_error}` : ''}
        </CardDescription>
      </CardHeader>
      {scan.llm_usage.calls > 0 && (
        <CardContent className="space-y-3 text-sm">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <div>
              <div className="text-xs text-muted-foreground">Cost</div>
              <div className="text-lg font-semibold tabular-nums">{usd(scan.llm_usage.cost_usd)}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground">Tokens</div>
              <div className="text-lg font-semibold tabular-nums">{scan.llm_usage.tokens.toLocaleString()}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground">Verified fixes</div>
              <div className="text-lg font-semibold tabular-nums">
                {scan.llm_usage.valid_fix_suggestions} / {scan.llm_usage.fix_suggestions}
              </div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground">Model calls</div>
              <div className="text-lg font-semibold tabular-nums">
                {scan.llm_usage.calls}
                {data && data.failed_calls > 0 && (
                  <span className="text-sm font-normal text-muted-foreground"> ({data.failed_calls} failed)</span>
                )}
              </div>
            </div>
          </div>
          {data && (
            <>
              <div>
                <div className="flex justify-between text-xs text-muted-foreground">
                  <span>Token budget</span>
                  <span className="tabular-nums">
                    {data.tokens_used.toLocaleString()} of {data.token_budget.toLocaleString()}
                  </span>
                </div>
                <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-muted">
                  <div
                    className={`h-full ${budgetShare > 0.9 ? 'bg-red-500' : 'bg-violet-500'}`}
                    style={{ width: `${budgetShare * 100}%` }}
                  />
                </div>
              </div>
              <ul className="divide-y text-xs">
                {data.by_purpose.map((row) => (
                  <li key={row.purpose} className="flex justify-between gap-2 py-1.5">
                    <span>{PURPOSE_LABEL[row.purpose]}</span>
                    <span className="text-muted-foreground tabular-nums">
                      {row.calls} calls · {(row.input_tokens + row.output_tokens).toLocaleString()} tokens ·{' '}
                      {usd(row.cost_usd)}
                    </span>
                  </li>
                ))}
              </ul>
              <p className="text-xs text-muted-foreground">
                {data.model} · {data.pricing_note}
              </p>
            </>
          )}
        </CardContent>
      )}
    </Card>
  )
}
