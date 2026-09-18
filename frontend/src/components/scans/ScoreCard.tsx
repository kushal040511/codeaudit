import { useQuery } from '@tanstack/react-query'
import { TriangleAlert } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { type ApiError, getScore, type Scan, type ScanScore } from '@/lib/api'
import { cn } from '@/lib/utils'

const GRADE_STYLE: Record<string, string> = {
  A: 'bg-emerald-600 text-white',
  B: 'bg-lime-600 text-white',
  C: 'bg-amber-500 text-white',
  D: 'bg-orange-600 text-white',
  F: 'bg-red-600 text-white',
}

function barColor(score: number) {
  if (score >= 80) return 'bg-emerald-500'
  if (score >= 55) return 'bg-amber-500'
  return 'bg-red-500'
}

export function ScoreCard({ scan }: { scan: Scan }) {
  const score = useQuery<ScanScore, ApiError>({
    queryKey: ['scan', scan.id, 'score', scan.score?.overall],
    queryFn: () => getScore(scan.id),
    enabled: scan.score !== null,
  })
  if (scan.score === null) return null
  const data = score.data

  return (
    <Card>
      <CardHeader className="flex flex-row items-start gap-4">
        <div
          aria-label={scan.score.grade ? `Grade ${scan.score.grade}` : 'Not scored'}
          className={cn(
            'flex size-14 shrink-0 items-center justify-center rounded-lg text-2xl font-bold',
            scan.score.grade ? GRADE_STYLE[scan.score.grade] : 'bg-muted text-muted-foreground',
          )}
        >
          {scan.score.grade ?? '–'}
        </div>
        <div className="min-w-0 space-y-1">
          <CardTitle>
            Score{' '}
            <span className="tabular-nums">{scan.score.overall === null ? 'n/a' : scan.score.overall.toFixed(1)}</span>
            <span className="text-sm font-normal text-muted-foreground"> / 100</span>
          </CardTitle>
          <CardDescription>
            Deterministic rubric v{scan.score.rubric_version}: severity-weighted findings, normalised by codebase size.
            AI suggestions never change it.
          </CardDescription>
          {scan.score.incomplete && (
            <p className="flex gap-1.5 text-sm text-amber-700 dark:text-amber-400">
              <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0" />
              Incomplete: {data?.incomplete_reasons.join('; ') ?? 'an analyzer failed'}. Not comparable with complete scores.
            </p>
          )}
        </div>
      </CardHeader>
      {data && (
        <CardContent className="grid gap-3 sm:grid-cols-2">
          {data.categories.map((category) => (
            <div key={category.category} className="space-y-1 text-sm">
              <div className="flex justify-between gap-2">
                <span>
                  {category.label}
                  {category.score !== null && (
                    <span className="text-xs text-muted-foreground"> · {Math.round(category.weight * 100)}%</span>
                  )}
                </span>
                <span className="tabular-nums">{category.score === null ? '—' : category.score.toFixed(0)}</span>
              </div>
              {category.score === null ? (
                <p className="text-xs text-muted-foreground">Excluded: {category.excluded_reason}</p>
              ) : (
                <>
                  <div className="h-1.5 overflow-hidden rounded-full bg-muted">
                    <div className={cn('h-full', barColor(category.score))} style={{ width: `${category.score}%` }} />
                  </div>
                  {category.rationale.length > 0 && (
                    <p className="truncate text-xs text-muted-foreground" title={category.rationale.join('\n')}>
                      Worst: {category.rationale[0]}
                    </p>
                  )}
                  {(category.deductions ?? []).map((line) => (
                    <p key={line.label} className="flex justify-between gap-2 text-xs text-muted-foreground">
                      <span className="truncate" title={line.label}>
                        {line.label}
                        {line.signal_score != null && <> · signal {Math.round(line.signal_score * 100)}%</>}
                      </span>
                      {line.signal !== null && <span className="tabular-nums">−{line.points.toFixed(1)}</span>}
                    </p>
                  ))}
                </>
              )}
            </div>
          ))}
        </CardContent>
      )}
    </Card>
  )
}
