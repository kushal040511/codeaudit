import { useMutation, useQuery } from '@tanstack/react-query'
import { Globe, Palette, ShieldAlert } from 'lucide-react'
import { type FormEvent, useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { RiskBadge } from '@/components/sites/RiskBadge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { analyzeSite, type ApiError, listSiteAnalyses, type SiteAnalysisListItem, type SiteAnalyzeCreated } from '@/lib/api'
import { useMe } from '@/lib/auth'
import { formatDateTime } from '@/lib/format'

const RECENT_KEY = 'codeaudit.recentSiteAnalyses'

type RecentEntry = { id: string; url: string; at: string }

function readRecent(): RecentEntry[] {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(RECENT_KEY) ?? '[]')
    return Array.isArray(parsed) ? (parsed as RecentEntry[]).slice(0, 10) : []
  } catch {
    return []
  }
}

function remember(entry: RecentEntry) {
  try {
    const next = [entry, ...readRecent().filter((e) => e.id !== entry.id)].slice(0, 10)
    localStorage.setItem(RECENT_KEY, JSON.stringify(next))
  } catch {
    // Private mode or storage disabled: history is a convenience only.
  }
}

export function SiteAnalyzerPage() {
  const navigate = useNavigate()
  const me = useMe()
  const [url, setUrl] = useState('')
  const [force, setForce] = useState(false)

  const history = useQuery<SiteAnalysisListItem[], ApiError>({
    queryKey: ['sites', 'mine'],
    queryFn: listSiteAnalyses,
    enabled: Boolean(me.data),
  })
  const analyze = useMutation<SiteAnalyzeCreated, ApiError, { url: string; force: boolean }>({
    mutationFn: ({ url, force }) => analyzeSite(url.trim(), force),
    onSuccess: (created, variables) => {
      remember({ id: created.analysis_id, url: variables.url.trim(), at: new Date().toISOString() })
      navigate(`/sites/${created.analysis_id}`)
    },
  })

  function submit(event: FormEvent) {
    event.preventDefault()
    if (url.trim() && !analyze.isPending) analyze.mutate({ url, force })
  }

  const recent: { id: string; url: string; at: string; score?: number | null; level?: SiteAnalysisListItem['risk_level'] }[] =
    me.data && history.data
      ? history.data.map((h) => ({ id: h.id, url: h.url, at: h.created_at, score: h.risk_score, level: h.risk_level }))
      : readRecent()

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Site Analyzer</h1>
        <p className="text-sm text-muted-foreground">
          Separate from code scans: analyze a live website for phishing or clone risk signals, and extract its design
          tokens.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Globe aria-hidden className="size-4" /> Analyze a URL
          </CardTitle>
          <CardDescription>
            The page is loaded in an isolated, sandboxed browser that can't reach internal networks. Downloads and popups
            are blocked.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit} className="space-y-3">
            <div className="flex flex-col gap-2 sm:flex-row">
              <label htmlFor="site-url" className="sr-only">
                Website URL
              </label>
              <input
                id="site-url"
                required
                placeholder="https://example.com"
                value={url}
                onChange={(event) => setUrl(event.target.value)}
                className="h-9 flex-1 rounded-lg border bg-background px-3 font-mono text-sm"
                autoComplete="off"
                spellCheck={false}
                inputMode="url"
              />
              <Button type="submit" disabled={analyze.isPending || !url.trim()} className="h-9">
                {analyze.isPending ? 'Checking URL…' : 'Analyze'}
              </Button>
            </div>
            <label className="flex items-center gap-2 text-xs text-muted-foreground">
              <input type="checkbox" checked={force} onChange={(event) => setForce(event.target.checked)} />
              Fetch again even if this URL was analyzed in the last few hours
            </label>
            {analyze.isError && (
              <p role="alert" className="text-sm text-destructive">
                {analyze.error.message}
              </p>
            )}
          </form>
          <div className="mt-5 grid gap-3 text-sm sm:grid-cols-2">
            <div className="flex gap-2">
              <ShieldAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
              <p className="text-muted-foreground">
                <span className="font-medium text-foreground">Risk signals.</span> Domain age, look-alike names,
                certificates, visual similarity to known brands, credential forms and reputation lists, each with its
                contribution to the score.
              </p>
            </div>
            <div className="flex gap-2">
              <Palette aria-hidden className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
              <p className="text-muted-foreground">
                <span className="font-medium text-foreground">Design tokens.</span> Colors, typography, spacing, radii
                and shadows from the page's computed CSS, as JSON, a Tailwind theme and CSS variables.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {recent.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Recent analyses</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="divide-y text-sm">
              {recent.map((entry) => (
                <li key={entry.id} className="flex items-center gap-3 py-2">
                  <Link to={`/sites/${entry.id}`} className="min-w-0 flex-1 truncate font-mono text-xs hover:underline">
                    {entry.url}
                  </Link>
                  {entry.score !== undefined && entry.score !== null && entry.level && (
                    <RiskBadge score={entry.score} level={entry.level} />
                  )}
                  <span className="shrink-0 text-xs text-muted-foreground">{formatDateTime(entry.at)}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
