import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { ArrowRight, CircleX, LoaderCircle, ShieldCheck, Sparkles } from 'lucide-react'
import { useState } from 'react'
import { FindingDrawer } from '@/components/fixes/FindingDrawer'
import { SeverityBadge } from '@/components/scans/SeverityBadge'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { describeFailures } from '@/lib/analyzers'
import {
  type ApiError,
  type Finding,
  type FindingPage,
  getFindings,
  type Scan,
  SEVERITIES,
  type Severity,
} from '@/lib/api'

const PAGE_SIZE = 25

function formatLines(finding: Finding): string {
  return finding.start_line === finding.end_line
    ? `${finding.start_line}`
    : `${finding.start_line}–${finding.end_line}`
}

function toggle<T>(values: T[], value: T): T[] {
  return values.includes(value) ? values.filter((v) => v !== value) : [...values, value]
}

function FixBadge({ finding }: { finding: Finding }) {
  if (finding.fix_status === 'generating') {
    return (
      <span className="inline-flex items-center gap-1 text-violet-700 dark:text-violet-400">
        <LoaderCircle aria-hidden className="size-3.5 animate-spin" /> Generating fix
      </span>
    )
  }
  if (finding.fix_status !== 'ready') return null
  if (finding.fix_validation_status === 'valid') {
    return (
      <span className="inline-flex items-center gap-1 text-violet-700 dark:text-violet-400">
        <Sparkles aria-hidden className="size-3.5" /> Verified fix
      </span>
    )
  }
  if (finding.fix_validation_status === 'no_patch') return <span>AI explanation</span>
  return (
    <span className="inline-flex items-center gap-1 text-red-700 dark:text-red-400">
      <CircleX aria-hidden className="size-3.5" /> Fix not verified
    </span>
  )
}

function FindingDetails({ finding, displayName }: { finding: Finding; displayName: (name: string) => string }) {
  const dep = finding.dependency
  return (
    <>
      <p className="text-sm">{finding.message}</p>
      {dep && (
        <p className="mt-1 flex flex-wrap items-center gap-1.5 font-mono text-xs">
          <span>
            {dep.package} {dep.installed_version}
          </span>
          {dep.fixed_version ? (
            <>
              <ArrowRight aria-label="upgrade to" className="size-3" />
              <span className="text-emerald-700 dark:text-emerald-400">{dep.fixed_version}</span>
            </>
          ) : (
            <span className="text-muted-foreground">(no fix available)</span>
          )}
          <span className="text-muted-foreground">· {dep.ecosystem}</span>
        </p>
      )}
      <p className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
        <span className="font-medium text-foreground/80">{displayName(finding.analyzer)}</span>
        <span className="font-mono break-all">{finding.rule_id}</span>
        {finding.corroborated_by.length > 0 && (
          <span
            className="inline-flex items-center gap-1 text-emerald-700 dark:text-emerald-400"
            title={finding.merged_from.map((m) => `${displayName(m.analyzer)}: ${m.rule_id}`).join('\n')}
          >
            <ShieldCheck aria-hidden className="size-3.5" />
            Also found by {finding.corroborated_by.map(displayName).join(', ')}
          </span>
        )}
        <FixBadge finding={finding} />
      </p>
    </>
  )
}

export function FindingsTable({ scan }: { scan: Scan }) {
  const [severities, setSeverities] = useState<Severity[]>([])
  const [analyzers, setAnalyzers] = useState<string[]>([])
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState<Finding | null>(null)

  const findings = useQuery<FindingPage, ApiError>({
    queryKey: ['scan', scan.id, 'findings', { severities, analyzers, page }],
    queryFn: () => getFindings(scan.id, { severity: severities, analyzer: analyzers, page, pageSize: PAGE_SIZE }),
    placeholderData: keepPreviousData,
    // Fix badges change while suggestions are generated.
    refetchInterval: scan.status === 'enriching' || scan.status === 'analysis_complete' ? 4000 : false,
  })

  const names = new Map(scan.analyzer_runs.map((run) => [run.analyzer, run.display_name]))
  const displayName = (name: string) => names.get(name) ?? name
  const completedRuns = scan.analyzer_runs.filter((run) => run.status === 'completed')
  const filtered = severities.length > 0 || analyzers.length > 0

  function clearFilters() {
    setSeverities([])
    setAnalyzers([])
    setPage(1)
  }

  const data = findings.data
  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1
  const failures = describeFailures(scan.analyzer_runs)

  return (
    <section className="space-y-3" aria-labelledby="findings-heading">
      <h2 id="findings-heading" className="text-lg font-semibold">
        Findings
      </h2>
      <div className="space-y-2">
        <div role="group" aria-label="Filter by severity" className="flex flex-wrap items-center gap-2">
          <span className="w-16 text-sm text-muted-foreground">Severity</span>
          {SEVERITIES.map((severity) => (
            <Button
              key={severity}
              size="sm"
              variant={severities.includes(severity) ? 'default' : 'outline'}
              aria-pressed={severities.includes(severity)}
              onClick={() => {
                setSeverities((current) => toggle(current, severity))
                setPage(1)
              }}
              className="capitalize"
            >
              {severity}
              <span className="tabular-nums opacity-70">{scan.finding_counts[severity]}</span>
            </Button>
          ))}
        </div>
        {completedRuns.length > 1 && (
          <div role="group" aria-label="Filter by analyzer" className="flex flex-wrap items-center gap-2">
            <span className="w-16 text-sm text-muted-foreground">Analyzer</span>
            {completedRuns.map((run) => (
              <Button
                key={run.analyzer}
                size="sm"
                variant={analyzers.includes(run.analyzer) ? 'default' : 'outline'}
                aria-pressed={analyzers.includes(run.analyzer)}
                title="Findings this analyzer reported, including ones another analyzer also found"
                onClick={() => {
                  setAnalyzers((current) => toggle(current, run.analyzer))
                  setPage(1)
                }}
              >
                {run.display_name}
                <span className="tabular-nums opacity-70">{scan.findings_by_analyzer[run.analyzer] ?? 0}</span>
              </Button>
            ))}
            {filtered && (
              <Button size="sm" variant="ghost" onClick={clearFilters}>
                Clear filters
              </Button>
            )}
          </div>
        )}
        {completedRuns.length <= 1 && filtered && (
          <Button size="sm" variant="ghost" onClick={clearFilters}>
            Clear filters
          </Button>
        )}
      </div>

      {findings.isError ? (
        <p role="alert" className="text-sm text-destructive">
          Could not load findings: {findings.error.message}
        </p>
      ) : !data ? (
        <p className="text-sm text-muted-foreground">Loading findings…</p>
      ) : data.total === 0 ? (
        <div className="rounded-lg border border-dashed p-10 text-center text-sm text-muted-foreground">
          {filtered
            ? 'No findings match the selected filters.'
            : scan.status === 'partial'
              ? `No findings from the analyzers that completed. This is not a clean result: ${failures}.`
              : `No findings. None of the ${scan.analyzer_summary.completed} analyzers reported issues in this codebase.`}
        </div>
      ) : (
        <>
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-24">Severity</TableHead>
                  <TableHead className="w-1/4">File</TableHead>
                  <TableHead className="w-20">Line</TableHead>
                  <TableHead>Issue</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody className={findings.isPlaceholderData ? 'opacity-60' : undefined}>
                {data.items.map((finding) => (
                  <TableRow
                    key={finding.id}
                    className="cursor-pointer"
                    onClick={() => setSelected(finding)}
                  >
                    <TableCell className="align-top">
                      <SeverityBadge severity={finding.severity} />
                    </TableCell>
                    <TableCell className="align-top font-mono text-xs break-all whitespace-normal">
                      {finding.file_path}
                    </TableCell>
                    <TableCell className="align-top font-mono text-xs">{formatLines(finding)}</TableCell>
                    <TableCell className="align-top whitespace-normal">
                      <button
                        type="button"
                        className="sr-only focus:not-sr-only"
                        onClick={(event) => {
                          event.stopPropagation()
                          setSelected(finding)
                        }}
                      >
                        Open finding details
                      </button>
                      <FindingDetails finding={finding} displayName={displayName} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <div className="flex items-center justify-between text-sm text-muted-foreground">
            <span>
              Showing {(data.page - 1) * data.page_size + 1}–{Math.min(data.page * data.page_size, data.total)} of{' '}
              {data.total}
            </span>
            <div className="flex gap-2">
              <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                Previous
              </Button>
              <Button size="sm" variant="outline" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
                Next
              </Button>
            </div>
          </div>
        </>
      )}
      <FindingDrawer scanId={scan.id} finding={selected} displayName={displayName} onClose={() => setSelected(null)} />
    </section>
  )
}
