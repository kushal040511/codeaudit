import { SeverityBadge } from '@/components/scans/SeverityBadge'
import { ISSUE_TYPE_LABELS } from '@/lib/architecture'
import type { ArchitectureIssue, ArchitectureIssueType } from '@/lib/api'
import { cn } from '@/lib/utils'

const ORDER: ArchitectureIssueType[] = ['circular_dependency', 'layer_violation', 'god_module', 'orphan_module']

type Props = {
  issues: ArchitectureIssue[]
  selectedId: number | null
  onSelect: (issueId: number | null) => void
}

export function IssuesList({ issues, selectedId, onSelect }: Props) {
  if (issues.length === 0) {
    return (
      <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
        No structural issues: no import cycles, layering violations, god modules or orphans.
      </p>
    )
  }
  return (
    <div className="space-y-4">
      {ORDER.map((type) => {
        const ofType = issues.filter((issue) => issue.issue_type === type)
        if (ofType.length === 0) return null
        return (
          <section key={type} aria-labelledby={`issues-${type}`} className="space-y-1.5">
            <h3 id={`issues-${type}`} className="text-xs font-semibold text-muted-foreground uppercase">
              {ISSUE_TYPE_LABELS[type]} <span className="tabular-nums">({ofType.length})</span>
            </h3>
            <ul className="space-y-1">
              {ofType.map((issue) => {
                const selected = issue.id === selectedId
                return (
                  <li key={issue.id}>
                    <button
                      type="button"
                      aria-pressed={selected}
                      onClick={() => onSelect(selected ? null : issue.id)}
                      className={cn(
                        'w-full rounded-md border p-2 text-left text-xs transition-colors hover:bg-muted',
                        selected && 'border-primary bg-muted',
                      )}
                    >
                      <div className="flex items-center gap-1.5">
                        <SeverityBadge severity={issue.severity} />
                        <span className="font-medium">{issue.title}</span>
                      </div>
                      <p className={cn('mt-1 text-muted-foreground', !selected && 'line-clamp-2')}>{issue.description}</p>
                    </button>
                  </li>
                )
              })}
            </ul>
          </section>
        )
      })}
    </div>
  )
}
