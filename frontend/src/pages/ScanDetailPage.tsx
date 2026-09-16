import { useQuery } from '@tanstack/react-query'
import { lazy, Suspense } from 'react'
import { Link, useParams } from 'react-router'
import { EnrichmentCard } from '@/components/llm/EnrichmentCard'
import { AnalyzerStatusPanel } from '@/components/scans/AnalyzerStatusPanel'
import { FindingsTable } from '@/components/scans/FindingsTable'
import { StatusIndicator } from '@/components/scans/StatusIndicator'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { describeFailures } from '@/lib/analyzers'
import { type ApiError, getScan, hasResults, isTerminalStatus, type Scan } from '@/lib/api'
import { formatDateTime, formatDuration } from '@/lib/format'

const POLL_INTERVAL_MS = 2000

// React Flow and dagre are only needed on the Architecture tab.
const ArchitectureTab = lazy(() =>
  import('@/components/architecture/ArchitectureTab').then((m) => ({ default: m.ArchitectureTab })),
)

export function ScanDetailPage() {
  const { scanId = '' } = useParams()

  const scanQuery = useQuery<Scan, ApiError>({
    queryKey: ['scan', scanId],
    queryFn: () => getScan(scanId),
    refetchInterval: (query) => {
      if (query.state.error?.status === 404) return false
      const scan = query.state.data
      return scan && isTerminalStatus(scan.status) ? false : POLL_INTERVAL_MS
    },
    retry: (failureCount, error) => error.status !== 404 && failureCount < 3,
  })

  const scan = scanQuery.data
  if (!scan) {
    if (scanQuery.isError) {
      const notFound = scanQuery.error.status === 404
      return (
        <div className="space-y-2">
          <h1 className="text-2xl font-semibold">{notFound ? 'Scan not found' : 'Could not load scan'}</h1>
          <p className="text-sm text-muted-foreground">{scanQuery.error.message}</p>
          <Link to="/upload" className="text-sm underline">
            Start a new scan
          </Link>
        </div>
      )
    }
    return <p className="text-sm text-muted-foreground">Loading scan…</p>
  }

  const duration = formatDuration(scan.started_at, scan.completed_at)

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-2xl font-semibold tracking-tight break-all">{scan.original_filename}</h1>
          <p className="font-mono text-xs text-muted-foreground">{scan.id}</p>
        </div>
        <StatusIndicator status={scan.status} />
      </div>

      {scanQuery.isError && (
        <p role="alert" className="text-sm text-destructive">
          Lost connection to the API, retrying… ({scanQuery.error.message})
        </p>
      )}

      <Card>
        <CardContent className="grid gap-4 text-sm sm:grid-cols-3">
          <div>
            <div className="text-muted-foreground">Created</div>
            <div>{formatDateTime(scan.created_at)}</div>
          </div>
          <div>
            <div className="text-muted-foreground">Started</div>
            <div>{formatDateTime(scan.started_at)}</div>
          </div>
          <div>
            <div className="text-muted-foreground">Completed</div>
            <div>
              {formatDateTime(scan.completed_at)}
              {duration && <span className="text-muted-foreground"> ({duration})</span>}
            </div>
          </div>
        </CardContent>
      </Card>

      {scan.detected_languages && scan.detected_languages.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="text-muted-foreground">Languages</span>
          {scan.detected_languages.map((lang) => (
            <Badge key={lang.language} variant="secondary" className="capitalize">
              {lang.language}
              {lang.file_count > 0 && <span className="tabular-nums opacity-70">{lang.file_count}</span>}
            </Badge>
          ))}
        </div>
      )}

      {scan.status === 'failed' && (
        <Card className="border-destructive/50">
          <CardHeader>
            <CardTitle className="text-destructive">Scan failed</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <p className="break-words">{scan.error_message ?? 'The scan failed for an unknown reason.'}</p>
            <Link to="/upload" className="underline">
              Try another upload
            </Link>
          </CardContent>
        </Card>
      )}

      {scan.status === 'partial' && (
        <Card role="alert" className="border-amber-300 bg-amber-50/60 dark:border-amber-900 dark:bg-amber-950/30">
          <CardHeader>
            <CardTitle className="text-amber-800 dark:text-amber-300">Partial results</CardTitle>
          </CardHeader>
          <CardContent className="space-y-1 text-sm">
            <p>
              {scan.analyzer_summary.completed} of {scan.analyzer_summary.total} analyzers completed.{' '}
              {describeFailures(scan.analyzer_runs)}.
            </p>
            <p className="text-muted-foreground">
              Issues those analyzers look for were not checked, so a missing finding here does not mean the code is
              clean.
            </p>
          </CardContent>
        </Card>
      )}

      {!isTerminalStatus(scan.status) && (
        <div className="rounded-lg border border-dashed p-10 text-center text-sm text-muted-foreground">
          {scan.status === 'queued' ? 'Waiting for a worker to pick up the scan…' : 'Running analyzers…'} Findings
          will appear here when the scan completes.
        </div>
      )}

      <AnalyzerStatusPanel scan={scan} />

      <EnrichmentCard scan={scan} />

      {hasResults(scan.status) && <ResultTabs scan={scan} />}
    </div>
  )
}

function ResultTabs({ scan }: { scan: Scan }) {
  const architecture = scan.analyzer_runs.find((run) => run.analyzer === 'architecture')
  const graphAvailable = architecture?.status === 'completed'
  return (
    <Tabs defaultValue="findings">
      <TabsList>
        <TabsTrigger value="findings">
          Findings <span className="tabular-nums opacity-70">{scan.total_findings}</span>
        </TabsTrigger>
        <TabsTrigger value="architecture">Architecture</TabsTrigger>
      </TabsList>
      <TabsContent value="findings">
        <FindingsTable scan={scan} />
      </TabsContent>
      <TabsContent value="architecture">
        {graphAvailable ? (
          <Suspense fallback={<p className="text-sm text-muted-foreground">Loading architecture view…</p>}>
            <ArchitectureTab
              scanId={scan.id}
              enrichmentNote={
                scan.enrichment_status === 'running' || scan.enrichment_status === 'pending'
                  ? 'It is still being generated.'
                  : (scan.enrichment_error ?? '')
              }
            />
          </Suspense>
        ) : (
          <div className="rounded-lg border border-dashed p-10 text-center text-sm text-muted-foreground">
            {!architecture || architecture.status === 'skipped'
              ? 'No architecture graph: the codebase has no Python, JavaScript or TypeScript modules.'
              : `No architecture graph: ${architecture.error_message ?? 'the architecture analysis did not complete.'}`}
          </div>
        )}
      </TabsContent>
    </Tabs>
  )
}
