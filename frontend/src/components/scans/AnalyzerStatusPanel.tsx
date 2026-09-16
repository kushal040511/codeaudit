import { CircleCheck, CircleMinus, CircleX, LoaderCircle, type LucideIcon, TimerOff, TriangleAlert } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { describeFailures, isFailedRun } from '@/lib/analyzers'
import type { AnalyzerRun, AnalyzerRunStatus, Scan } from '@/lib/api'
import { formatMilliseconds } from '@/lib/format'
import { cn } from '@/lib/utils'

const RUN_STATUS: Record<AnalyzerRunStatus, { label: string; icon: LucideIcon; className: string; spin?: boolean }> =
  {
    running: { label: 'Running', icon: LoaderCircle, className: 'text-blue-600 dark:text-blue-400', spin: true },
    completed: { label: 'Completed', icon: CircleCheck, className: 'text-emerald-600 dark:text-emerald-400' },
    failed: { label: 'Failed', icon: CircleX, className: 'text-destructive' },
    timed_out: { label: 'Timed out', icon: TimerOff, className: 'text-destructive' },
    skipped: { label: 'Not applicable', icon: CircleMinus, className: 'text-muted-foreground' },
  }

function summaryLine(scan: Scan): string {
  const { total, completed, running } = scan.analyzer_summary
  const failures = describeFailures(scan.analyzer_runs)
  const parts = [`${completed} of ${total} analyzers completed`]
  if (running > 0) parts.push(`${running} still running`)
  if (failures) parts.push(failures)
  return parts.join(' · ')
}

function RunRow({ run }: { run: AnalyzerRun }) {
  const { label, icon: Icon, className, spin } = RUN_STATUS[run.status]
  const failed = isFailedRun(run)
  return (
    <li className="grid grid-cols-[1.25rem_1fr_auto] gap-x-3 gap-y-1 py-3 first:pt-0 last:pb-0">
      <Icon aria-hidden className={cn('mt-0.5 size-5', className, spin && 'animate-spin')} />
      <div className="min-w-0">
        <div className="flex flex-wrap items-baseline gap-x-2">
          <span className="font-medium">{run.display_name}</span>
          <span className={cn('text-sm', className)}>{label}</span>
        </div>
        {run.error_message && (
          <p className={cn('mt-0.5 text-sm break-words', failed ? 'text-destructive' : 'text-muted-foreground')}>
            {run.error_message}
          </p>
        )}
        {run.warnings.map((warning) => (
          <p key={warning} className="mt-0.5 flex gap-1.5 text-sm text-amber-700 dark:text-amber-400">
            <TriangleAlert aria-hidden className="mt-0.5 size-3.5 shrink-0" />
            <span className="break-words">{warning}</span>
          </p>
        ))}
      </div>
      <div className="text-right text-sm tabular-nums text-muted-foreground">
        {run.status !== 'skipped' && <div>{run.status === 'running' ? '…' : formatMilliseconds(run.duration_ms)}</div>}
        {run.finding_count !== null && (
          <div>
            {run.finding_count} {run.finding_count === 1 ? 'finding' : 'findings'}
          </div>
        )}
      </div>
    </li>
  )
}

export function AnalyzerStatusPanel({ scan }: { scan: Scan }) {
  if (scan.analyzer_runs.length === 0) return null
  const hasWarnings = scan.analyzer_runs.some((run) => run.warnings.length > 0)

  return (
    <Card>
      <CardHeader>
        <CardTitle>Analyzers</CardTitle>
        <CardDescription>
          {summaryLine(scan)}
          {hasWarnings && ' · some coverage warnings'}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ul className="divide-y">
          {scan.analyzer_runs.map((run) => (
            <RunRow key={run.analyzer} run={run} />
          ))}
        </ul>
        {scan.findings_before_dedup > scan.total_findings && (
          <p className="mt-4 border-t pt-3 text-sm text-muted-foreground">
            {scan.findings_before_dedup} findings reported, {scan.total_findings} after merging issues found by more
            than one rule or analyzer.
          </p>
        )}
      </CardContent>
    </Card>
  )
}
