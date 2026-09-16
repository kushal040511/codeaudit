import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ExternalLink, GitPullRequest, LoaderCircle, TriangleAlert } from 'lucide-react'
import { type ReactNode, useMemo, useState } from 'react'
import { PullRequestPreviewDialog } from '@/components/pullrequests/PullRequestPreviewDialog'
import { SeverityBadge } from '@/components/scans/SeverityBadge'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  type ApiError,
  type FixCandidate,
  getFixCandidates,
  githubLoginUrl,
  listPullRequests,
  previewPullRequest,
  projectScore,
  type PullRequest,
  type PullRequestPreview,
  type Scan,
  type ScoreProjection,
} from '@/lib/api'
import { useMe } from '@/lib/auth'
import { formatDateTime } from '@/lib/format'
import { cn } from '@/lib/utils'

/** Candidates sharing one patch fix several findings: they're selected together. */
function groupKey(candidate: FixCandidate): string {
  return candidate.patch
}

const STATUS_STYLE: Record<PullRequest['status'], string> = {
  previewed: '',
  creating: 'bg-sky-600 text-white',
  open: 'bg-emerald-600 text-white',
  failed: 'bg-red-600 text-white',
}

function PullRequestStatusPanel({ scanId, enabled }: { scanId: string; enabled: boolean }) {
  const prs = useQuery<PullRequest[], ApiError>({
    queryKey: ['scan', scanId, 'pull-requests'],
    queryFn: () => listPullRequests(scanId),
    enabled,
    refetchInterval: (query) => (query.state.data?.some((pr) => pr.status === 'creating') ? 2000 : false),
  })
  if (!prs.data?.length) return null
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Pull requests</CardTitle>
      </CardHeader>
      <CardContent>
        <ul className="divide-y text-sm">
          {prs.data.map((pr) => (
            <li key={pr.id} className="space-y-1 py-3 first:pt-0 last:pb-0">
              <div className="flex flex-wrap items-center gap-2">
                <Badge className={STATUS_STYLE[pr.status]}>
                  {pr.status === 'creating' && <LoaderCircle aria-hidden className="animate-spin" />}
                  {pr.status}
                </Badge>
                <span className="font-medium">{pr.title}</span>
                {pr.pr_url && (
                  <a href={pr.pr_url} target="_blank" rel="noreferrer" className="ml-auto inline-flex items-center gap-1 underline">
                    {pr.repo_full_name}#{pr.pr_number} <ExternalLink aria-hidden className="size-3.5" />
                  </a>
                )}
              </div>
              <p className="text-xs text-muted-foreground">
                <code className="font-mono">
                  {pr.head_repo_full_name}:{pr.branch}
                </code>{' '}
                → <code className="font-mono">{pr.base_branch}</code> · {pr.commits.length || pr.included_suggestion_ids.length}{' '}
                {pr.commits.length ? 'commits' : 'fixes'} · confirmed {formatDateTime(pr.confirmed_at)}
              </p>
              {pr.status === 'failed' && (
                <p role="alert" className="text-destructive">
                  {pr.error_message} <span className="font-mono text-xs">({pr.error_code})</span>
                </p>
              )}
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  )
}

/** Why this user can't open a pull request from the scan, or null if they can. */
function useEligibility(scan: Scan): ReactNode {
  const me = useMe()
  if (scan.source !== 'github') {
    return 'Pull requests can be opened for scans of GitHub repositories. This scan was an upload.'
  }
  if (!scan.owned_by_you) {
    return me.data
      ? 'Only the person who started this scan can open a pull request from it.'
      : 'Sign in with GitHub and scan the repository to open a pull request.'
  }
  if (!me.data?.github?.connected) {
    return (
      <>
        <a className="underline" href={githubLoginUrl({ next: `/scans/${scan.id}` })}>
          Connect GitHub
        </a>{' '}
        to open a pull request.
      </>
    )
  }
  return null
}

export function FixesTab({ scan }: { scan: Scan }) {
  const queryClient = useQueryClient()
  const me = useMe()
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [preview, setPreview] = useState<PullRequestPreview | null>(null)
  const [lastOptions, setLastOptions] = useState<{ use_fork?: boolean; branch?: string }>({})

  const candidates = useQuery<FixCandidate[], ApiError>({
    queryKey: ['scan', scan.id, 'fixes'],
    queryFn: () => getFixCandidates(scan.id),
    refetchInterval: scan.status === 'enriching' || scan.status === 'analysis_complete' ? 5000 : false,
  })

  const groups = useMemo(() => {
    const map = new Map<string, FixCandidate[]>()
    for (const candidate of candidates.data ?? []) {
      const key = groupKey(candidate)
      map.set(key, [...(map.get(key) ?? []), candidate])
    }
    return [...map.entries()]
  }, [candidates.data])

  const chosen = groups.filter(([key]) => selected.has(key)).flatMap(([, members]) => members)
  const findingIds = [...new Set(chosen.flatMap((c) => [c.finding_id, ...c.shared_with_finding_ids]))].sort((a, b) => a - b)
  const suggestionIds = chosen.map((c) => c.suggestion_id)

  const projection = useQuery<ScoreProjection, ApiError>({
    queryKey: ['scan', scan.id, 'projection', findingIds],
    queryFn: () => projectScore(scan.id, findingIds),
    enabled: findingIds.length > 0 && scan.score !== null,
    placeholderData: keepPreviousData,
  })

  const makePreview = useMutation<PullRequestPreview, ApiError, { use_fork?: boolean; branch?: string }>({
    mutationFn: (options) => previewPullRequest(scan.id, { suggestion_ids: suggestionIds, ...options }),
    onSuccess: (result, options) => {
      setLastOptions(options)
      setPreview(result)
    },
  })

  const blocked = useEligibility(scan)
  const canPreview =
    blocked === null && me.data?.auth_method === 'session' && suggestionIds.length > 0 && !makePreview.isPending

  function toggle(key: string) {
    setSelected((current) => {
      const next = new Set(current)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  const data = candidates.data
  const current = scan.score?.overall ?? null
  const delta = findingIds.length === 0 ? 0 : projection.data?.delta

  return (
    <div className="space-y-4">
      <PullRequestStatusPanel scanId={scan.id} enabled={scan.owned_by_you && Boolean(me.data)} />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Verified fixes</CardTitle>
          <CardDescription>
            Only patches that apply cleanly to the scanned commit and still parse are listed. They are AI-generated:
            review them before merging.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {candidates.isError ? (
            <p role="alert" className="text-sm text-destructive">
              Could not load fixes: {candidates.error.message}
            </p>
          ) : !data ? (
            <p className="text-sm text-muted-foreground">Loading fixes…</p>
          ) : data.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No verified fixes for this scan
              {scan.enrichment_status === 'running' || scan.enrichment_status === 'pending' ? ' yet' : ''}. Suggestions
              are generated for the highest-impact findings; open a finding to request one.
            </p>
          ) : (
            <>
              <div className="sticky top-0 z-10 flex flex-wrap items-center gap-3 rounded-lg border bg-background/95 p-3 backdrop-blur">
                <div className="text-sm">
                  <span className="font-medium tabular-nums">{chosen.length}</span> of {data.length} fixes selected
                </div>
                {current !== null && (
                  <div className="text-sm tabular-nums" aria-live="polite">
                    Score {current.toFixed(1)} →{' '}
                    <strong>{delta === undefined || delta === null ? '…' : (current + delta).toFixed(1)}</strong>
                    {delta ? (
                      <span className="ml-1 text-emerald-700 dark:text-emerald-400">+{delta.toFixed(2)}</span>
                    ) : null}
                    {projection.isFetching && <LoaderCircle aria-hidden className="ml-1 inline size-3.5 animate-spin" />}
                  </div>
                )}
                <div className="ml-auto flex flex-wrap items-center gap-2">
                  <Button size="sm" variant="ghost" onClick={() => setSelected(new Set(groups.map(([key]) => key)))}>
                    Select all
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())} disabled={selected.size === 0}>
                    Clear
                  </Button>
                  <Button size="sm" disabled={!canPreview} onClick={() => makePreview.mutate({})}>
                    <GitPullRequest aria-hidden />
                    {makePreview.isPending ? 'Preparing preview…' : 'Preview pull request'}
                  </Button>
                </div>
                {scan.repository && blocked === null && (
                  <p className="flex w-full items-center gap-1.5 text-xs text-amber-800 dark:text-amber-300">
                    <TriangleAlert aria-hidden className="size-3.5" />
                    Creating a pull request writes a branch and commits to{' '}
                    <strong>{scan.repository.full_name}</strong> (or your fork) after you confirm a preview.
                  </p>
                )}
                {blocked !== null && <p className="w-full text-xs text-muted-foreground">{blocked}</p>}
              </div>
              {makePreview.isError && (
                <p role="alert" className="text-sm text-destructive">
                  {makePreview.error.message}
                  {makePreview.error.code === 'github_auth_required' && (
                    <>
                      {' '}
                      <a className="underline" href={githubLoginUrl({ next: `/scans/${scan.id}` })}>
                        Reconnect GitHub
                      </a>
                    </>
                  )}
                </p>
              )}

              <ul className="divide-y rounded-lg border">
                {groups.map(([key, members]) => {
                  const lead = members[0]
                  const impact = members.reduce((sum, m) => sum + (m.score_impact ?? 0), 0)
                  const checked = selected.has(key)
                  return (
                    <li key={key}>
                      <label className={cn('flex cursor-pointer gap-3 p-3 hover:bg-muted/40', checked && 'bg-muted/40')}>
                        <input type="checkbox" checked={checked} onChange={() => toggle(key)} className="mt-1 size-4 shrink-0" />
                        <div className="min-w-0 flex-1 space-y-1">
                          {members.map((member) => (
                            <div key={member.suggestion_id} className="flex flex-wrap items-center gap-2 text-sm">
                              <SeverityBadge severity={member.severity} />
                              <span className="font-mono text-xs break-all">
                                {member.file_path}:{member.start_line}
                              </span>
                              <span className="font-mono text-xs text-muted-foreground">{member.rule_id}</span>
                            </div>
                          ))}
                          {lead.explanation && <p className="text-sm text-muted-foreground">{lead.explanation}</p>}
                          <p className="flex flex-wrap gap-x-3 text-xs text-muted-foreground">
                            {impact >= 0.01 && <span className="tabular-nums">+{impact.toFixed(2)} pts</span>}
                            {lead.confidence && <span>confidence {lead.confidence}</span>}
                            {lead.breaking_risk && <span>breaking risk {lead.breaking_risk}</span>}
                            {members.length > 1 && <span>one patch fixes {members.length} findings</span>}
                          </p>
                        </div>
                      </label>
                    </li>
                  )
                })}
              </ul>
            </>
          )}
        </CardContent>
      </Card>

      <PullRequestPreviewDialog
        key={preview?.id ?? 'none'}
        preview={preview}
        repreviewing={makePreview.isPending}
        onRepreview={(options) => makePreview.mutate({ ...lastOptions, ...options })}
        onClose={() => setPreview(null)}
        onConfirmed={() => {
          setPreview(null)
          setSelected(new Set())
          void queryClient.invalidateQueries({ queryKey: ['scan', scan.id, 'pull-requests'] })
        }}
      />
    </div>
  )
}
