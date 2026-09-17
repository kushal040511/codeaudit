import { useQuery } from '@tanstack/react-query'
import { Check, LoaderCircle } from 'lucide-react'
import { Link, useParams } from 'react-router'
import { DesignPanel } from '@/components/sites/DesignPanel'
import { RiskPanel } from '@/components/sites/RiskPanel'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { apiAsset, type ApiError, getSiteAnalysis, type SiteAnalysis } from '@/lib/api'
import { formatDateTime } from '@/lib/format'
import { cn } from '@/lib/utils'

const STEPS = [
  { key: 'queued', label: 'Queued' },
  { key: 'capturing', label: 'Loading the page in a sandboxed browser' },
  { key: 'assessing_risk', label: 'Checking domain, certificate, visuals and reputation' },
  { key: 'extracting_design', label: 'Extracting design tokens' },
] as const

function Progress({ analysis }: { analysis: SiteAnalysis }) {
  const current = analysis.status === 'queued' ? 0 : Math.max(0, STEPS.findIndex((s) => s.key === analysis.stage))
  return (
    <Card>
      <CardContent className="py-6">
        <ol className="space-y-3" aria-live="polite">
          {STEPS.map((step, index) => (
            <li key={step.key} className={cn('flex items-center gap-3 text-sm', index > current && 'text-muted-foreground')}>
              {index < current ? (
                <Check aria-hidden className="size-4 text-emerald-600" />
              ) : index === current ? (
                <LoaderCircle aria-hidden className="size-4 animate-spin" />
              ) : (
                <span aria-hidden className="size-4 rounded-full border" />
              )}
              {step.label}
            </li>
          ))}
        </ol>
      </CardContent>
    </Card>
  )
}

function CaptureDetails({ analysis }: { analysis: SiteAnalysis }) {
  const capture = analysis.capture
  if (!capture) return null
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">What was captured</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-4 text-sm md:grid-cols-[1fr_20rem]">
        <div className="space-y-3">
          <div>
            <div className="text-xs text-muted-foreground">Page title</div>
            <div className="break-words">{capture.title || '(none)'}</div>
          </div>
          <div>
            <div className="text-xs text-muted-foreground">Redirect chain</div>
            <ol className="space-y-0.5 font-mono text-xs">
              {capture.redirect_chain.map((hop, index) => (
                <li key={`${hop.url}-${index}`} className="break-all">
                  {hop.status ?? '→'} {hop.url}
                </li>
              ))}
            </ol>
          </div>
          {capture.forms.length > 0 && (
            <div>
              <div className="text-xs text-muted-foreground">Forms</div>
              <ul className="space-y-0.5 text-xs">
                {capture.forms.map((form, index) => (
                  <li key={index} className="break-all">
                    <span className="font-mono uppercase">{form.method}</span> {form.action}{' '}
                    <span className="text-muted-foreground">({form.input_types.join(', ')})</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {capture.link_domains.length > 0 && (
            <div>
              <div className="text-xs text-muted-foreground">Outbound link domains</div>
              <p className="text-xs break-words">
                {capture.link_domains.slice(0, 15).map(([domain, count]) => `${domain} (${count})`).join(', ')}
              </p>
            </div>
          )}
          {capture.blocked_requests.length > 0 && (
            <p className="text-xs text-amber-700 dark:text-amber-400">
              {capture.blocked_requests.length} request(s) to internal or forbidden addresses were blocked.
            </p>
          )}
        </div>
        {analysis.screenshot_url && (
          <a href={apiAsset(analysis.full_screenshot_url ?? analysis.screenshot_url)} target="_blank" rel="noreferrer">
            <img src={apiAsset(analysis.screenshot_url)} alt="Screenshot of the analyzed page" className="w-full rounded-md border" />
            <span className="text-xs text-muted-foreground">Open full-page screenshot</span>
          </a>
        )}
      </CardContent>
    </Card>
  )
}

export function SiteAnalysisPage() {
  const { analysisId = '' } = useParams()
  const query = useQuery<SiteAnalysis, ApiError>({
    queryKey: ['sites', analysisId],
    queryFn: () => getSiteAnalysis(analysisId),
    refetchInterval: (q) => {
      const status = q.state.data?.status
      return status === 'completed' || status === 'failed' || q.state.error?.status === 404 ? false : 1500
    },
    retry: (count, error) => error.status !== 404 && count < 3,
  })
  const analysis = query.data

  if (!analysis) {
    return query.isError ? (
      <div className="space-y-2">
        <h1 className="text-2xl font-semibold">{query.error.status === 404 ? 'Analysis not found' : 'Could not load analysis'}</h1>
        <p className="text-sm text-muted-foreground">{query.error.message}</p>
        <Link to="/sites" className="text-sm underline">Analyze a URL</Link>
      </div>
    ) : (
      <p className="text-sm text-muted-foreground">Loading…</p>
    )
  }

  return (
    <div className="space-y-6">
      <div className="min-w-0">
        <Link to="/sites" className="text-xs text-muted-foreground hover:underline">← Site Analyzer</Link>
        <h1 className="text-2xl font-semibold tracking-tight break-all">{analysis.final_url ?? analysis.normalized_url}</h1>
        <p className="text-xs text-muted-foreground">
          Requested {analysis.url} · {formatDateTime(analysis.created_at)}
          {analysis.cached_from_id && ' · reused a recent capture of this URL'}
        </p>
      </div>

      {analysis.status === 'failed' ? (
        <Card className="border-destructive/50">
          <CardHeader>
            <CardTitle className="text-destructive">Analysis failed</CardTitle>
          </CardHeader>
          <CardContent className="text-sm break-words">{analysis.error_message}</CardContent>
        </Card>
      ) : analysis.status !== 'completed' ? (
        <Progress analysis={analysis} />
      ) : (
        <Tabs defaultValue="risk">
          <TabsList>
            <TabsTrigger value="risk">Risk signals</TabsTrigger>
            <TabsTrigger value="design">Design tokens</TabsTrigger>
            <TabsTrigger value="capture">Capture</TabsTrigger>
          </TabsList>
          <TabsContent value="risk">
            {analysis.risk && <RiskPanel analysis={analysis} risk={analysis.risk} />}
          </TabsContent>
          <TabsContent value="design">
            {analysis.design && <DesignPanel analysisId={analysis.id} tokens={analysis.design.tokens} notes={analysis.design.notes} />}
          </TabsContent>
          <TabsContent value="capture">
            <CaptureDetails analysis={analysis} />
          </TabsContent>
        </Tabs>
      )}
    </div>
  )
}
