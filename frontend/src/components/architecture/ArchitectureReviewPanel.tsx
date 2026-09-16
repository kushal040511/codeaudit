import { useQuery } from '@tanstack/react-query'
import { ShieldAlert, Sparkles } from 'lucide-react'
import { SeverityBadge } from '@/components/scans/SeverityBadge'
import { Badge } from '@/components/ui/badge'
import { citationHighlight, formatPercent, type Highlight } from '@/lib/architecture'
import type { ApiError, ArchitectureGraph, ArchitectureReview, ReviewIssue, Severity } from '@/lib/api'
import { getArchitectureReview } from '@/lib/api'
import { cn } from '@/lib/utils'

const SEVERITIES = new Set(['critical', 'error', 'warning', 'info'])

function IssueCard({
  issue,
  graph,
  highlightKey,
  onHighlight,
}: {
  issue: ReviewIssue
  graph: ArchitectureGraph
  highlightKey: string | null
  onHighlight: (highlight: Highlight | null) => void
}) {
  return (
    <li className="space-y-2 rounded-md border p-2.5 text-xs">
      <div className="flex items-start gap-1.5">
        {SEVERITIES.has(issue.severity) && <SeverityBadge severity={issue.severity as Severity} />}
        <span className="font-medium">{issue.title}</span>
      </div>
      <p className="text-muted-foreground">{issue.why_it_matters}</p>
      <div className="flex flex-wrap gap-1">
        {issue.evidence.map((evidence) => {
          const highlight = citationHighlight(evidence, graph)
          const active = highlightKey === highlight.key
          return (
            <button
              key={evidence}
              type="button"
              aria-pressed={active}
              title={highlight.node_ids.length ? 'Highlight in the graph' : 'Not in the current graph view'}
              onClick={() => onHighlight(active ? null : highlight)}
              className={cn(
                'rounded border px-1.5 py-0.5 text-left font-mono break-all hover:bg-muted',
                active && 'border-primary bg-muted',
              )}
            >
              {evidence}
            </button>
          )
        })}
      </div>
      {issue.refactor_steps.length > 0 && (
        <ol className="list-decimal space-y-0.5 pl-4">
          {issue.refactor_steps.map((step) => (
            <li key={step}>{step}</li>
          ))}
        </ol>
      )}
      {issue.rejected_evidence.length > 0 && (
        <p className="flex gap-1 text-amber-700 dark:text-amber-400">
          <ShieldAlert aria-hidden className="mt-px size-3.5 shrink-0" />
          {issue.rejected_evidence.length} citation(s) removed: not in this repository's graph (
          {issue.rejected_evidence.map((r) => r.evidence).join(', ')}).
        </p>
      )}
    </li>
  )
}

type Props = {
  scanId: string
  graph: ArchitectureGraph
  enrichmentNote: string
  highlightKey: string | null
  onHighlight: (highlight: Highlight | null) => void
}

export function ArchitectureReviewPanel({ scanId, graph, enrichmentNote, highlightKey, onHighlight }: Props) {
  const review = useQuery<ArchitectureReview, ApiError>({
    queryKey: ['scan', scanId, 'architecture-review'],
    queryFn: () => getArchitectureReview(scanId),
    retry: (count, error) => error.status !== 404 && count < 2,
  })

  if (review.isPending) return <p className="text-sm text-muted-foreground">Loading review…</p>
  if (review.isError) {
    return (
      <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
        {review.error.status === 404 ? `No AI architecture review. ${enrichmentNote}` : review.error.message}
      </p>
    )
  }
  const data = review.data
  if (data.status === 'failed') {
    return <p className="text-sm text-destructive">The architecture review failed: {data.error_message}</p>
  }
  return (
    <div className="space-y-4 text-sm">
      <div className="space-y-1.5">
        <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Sparkles aria-hidden className="size-3.5 text-violet-600" /> {data.model}
        </p>
        <p>{data.summary}</p>
        <div className="flex flex-wrap gap-1.5">
          <Badge
            variant="outline"
            title="Cited modules that don't exist in this repository's graph, as a share of all citations"
          >
            Hallucinated citations:{' '}
            {data.hallucination_rate === null
              ? 'n/a'
              : `${formatPercent(data.hallucination_rate)} (${data.citations_invalid}/${data.citations_total})`}
          </Badge>
          {data.dropped_issues.length > 0 && (
            <Badge variant="outline">{data.dropped_issues.length} unsupported issue(s) removed</Badge>
          )}
        </div>
      </div>

      {data.strengths.length > 0 && (
        <section className="space-y-1">
          <h3 className="text-xs font-semibold text-muted-foreground uppercase">Strengths</h3>
          <ul className="list-disc space-y-0.5 pl-4 text-xs">
            {data.strengths.map((strength) => (
              <li key={strength}>{strength}</li>
            ))}
          </ul>
        </section>
      )}

      <section className="space-y-1.5">
        <h3 className="text-xs font-semibold text-muted-foreground uppercase">Issues ({data.issues.length})</h3>
        <ul className="space-y-2">
          {data.issues.map((issue) => (
            <IssueCard key={issue.title} issue={issue} graph={graph} highlightKey={highlightKey} onHighlight={onHighlight} />
          ))}
        </ul>
      </section>

      {data.suggested_target_structure && (
        <section className="space-y-1">
          <h3 className="text-xs font-semibold text-muted-foreground uppercase">Suggested structure</h3>
          <pre className="overflow-x-auto rounded-md border bg-muted/40 p-2 font-mono text-xs whitespace-pre">
            {data.suggested_target_structure}
          </pre>
        </section>
      )}
    </div>
  )
}
