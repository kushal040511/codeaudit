import { useMutation } from '@tanstack/react-query'
import { GitBranch, GitCommitHorizontal, GitFork, GitPullRequest, TriangleAlert } from 'lucide-react'
import { useState } from 'react'
import { UnifiedDiff } from '@/components/pullrequests/UnifiedDiff'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { type ApiError, confirmPullRequest, type PullRequest, type PullRequestPreview } from '@/lib/api'

const CHECK_LABEL: Record<string, string> = {
  no_longer_applies: 'no longer applies to the current branch',
  conflicts: 'conflicts with another selected fix',
  syntax_error: 'would break parsing when combined',
}

type Props = {
  preview: PullRequestPreview | null
  /** Re-run the preview with different options (fork, branch name). */
  onRepreview: (options: { use_fork?: boolean; branch?: string }) => void
  repreviewing: boolean
  onClose: () => void
  onConfirmed: (pr: PullRequest) => void
}

export function PullRequestPreviewDialog({ preview, onRepreview, repreviewing, onClose, onConfirmed }: Props) {
  // Keyed by preview id in the parent: a new preview starts with fresh state.
  const [title, setTitle] = useState(preview?.title ?? '')
  const [body, setBody] = useState(preview?.body ?? '')
  const [reviewed, setReviewed] = useState(false)

  const confirm = useMutation<PullRequest, ApiError, void>({
    mutationFn: () => confirmPullRequest(preview!.id, { title: title.trim(), body }),
    onSuccess: onConfirmed,
  })

  if (!preview) return null
  const blocking = preview.blocking
  const notApplied = preview.patch_checks.filter((check) => check.status !== 'applies')
  const canConfirm = blocking.length === 0 && preview.planned_commits.length > 0 && reviewed && title.trim().length > 0
  const score = preview.score

  return (
    <Dialog open onOpenChange={(open) => !open && !confirm.isPending && onClose()}>
      <DialogContent>
        <div className="space-y-1 border-b p-5">
          <DialogTitle>Review pull request</DialogTitle>
          <DialogDescription>
            Nothing has been written yet. Check the exact changes below, then confirm.
          </DialogDescription>
        </div>

        <div className="min-h-0 flex-1 space-y-5 overflow-y-auto p-5">
          <div
            role="note"
            className="flex gap-3 rounded-lg border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-200"
          >
            <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0" />
            <div className="space-y-1">
              <p className="font-medium">Confirming writes to GitHub as you.</p>
              <p>
                {preview.use_fork && <>Forks <strong>{preview.repo_full_name}</strong> to your account if needed, then </>}
                Creates branch <code className="font-mono">{preview.branch}</code> in{' '}
                <strong>{preview.writes_to}</strong> with {preview.planned_commits.length} commit
                {preview.planned_commits.length === 1 ? '' : 's'}, and opens a pull request against{' '}
                <code className="font-mono">
                  {preview.repo_full_name}:{preview.base_branch}
                </code>
                . Your default branch is not modified.
              </p>
            </div>
          </div>

          {blocking.length > 0 && (
            <div role="alert" className="space-y-2 rounded-lg border border-destructive/40 bg-destructive/5 p-3 text-sm">
              {blocking.map((issue) => (
                <div key={issue.code} className="space-y-2">
                  <p className="text-destructive">{issue.message}</p>
                  {issue.code === 'fork_required' && (
                    <Button size="sm" variant="outline" disabled={repreviewing} onClick={() => onRepreview({ use_fork: true })}>
                      <GitFork aria-hidden /> Open from a fork instead
                    </Button>
                  )}
                  {issue.code === 'branch_exists' && preview.suggested_branch && (
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={repreviewing}
                      onClick={() => onRepreview({ branch: preview.suggested_branch!, use_fork: preview.use_fork })}
                    >
                      <GitBranch aria-hidden /> Use {preview.suggested_branch}
                    </Button>
                  )}
                </div>
              ))}
            </div>
          )}

          {preview.head_moved && (
            <p className="text-sm text-muted-foreground">
              <strong className="text-foreground">{preview.base_branch}</strong> has new commits since the scan (
              <code className="font-mono">{preview.scanned_sha.slice(0, 7)}</code> →{' '}
              <code className="font-mono">{preview.base_sha.slice(0, 7)}</code>). Every patch was re-checked against the
              current head.
            </p>
          )}

          {(notApplied.length > 0 || preview.excluded.length > 0) && (
            <div className="space-y-1 text-sm">
              <h3 className="font-medium">Left out</h3>
              <ul className="list-disc space-y-0.5 pl-5 text-muted-foreground">
                {notApplied.map((check) => (
                  <li key={check.suggestion_ids.join(',')}>
                    Fix for {check.paths.join(', ')}: {CHECK_LABEL[check.status] ?? check.status}
                  </li>
                ))}
                {preview.excluded.map((item) => (
                  <li key={item.suggestion_id}>
                    Suggestion {item.suggestion_id}: {item.reason}
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="grid gap-4 md:grid-cols-[1fr_16rem]">
            <div className="space-y-3">
              <div className="space-y-1.5">
                <label htmlFor="pr-title" className="text-sm font-medium">
                  Title
                </label>
                <input
                  id="pr-title"
                  value={title}
                  maxLength={255}
                  onChange={(event) => setTitle(event.target.value)}
                  className="h-9 w-full rounded-lg border bg-background px-3 text-sm"
                />
              </div>
              <div className="space-y-1.5">
                <label htmlFor="pr-body" className="text-sm font-medium">
                  Description
                </label>
                <textarea
                  id="pr-body"
                  value={body}
                  onChange={(event) => setBody(event.target.value)}
                  rows={10}
                  className="w-full rounded-lg border bg-background p-3 font-mono text-xs"
                />
                <p className="text-xs text-muted-foreground">
                  The note that the changes are AI-generated and need human review is always kept.
                </p>
              </div>
            </div>
            <div className="space-y-3 text-sm">
              <div className="rounded-lg border p-3">
                <div className="text-muted-foreground">Projected score</div>
                {score.current === null || score.projected === null ? (
                  <div>n/a</div>
                ) : (
                  <div className="text-lg font-semibold tabular-nums">
                    {score.current.toFixed(1)} → {score.projected.toFixed(1)}{' '}
                    <span className="text-sm text-emerald-700 dark:text-emerald-400">
                      +{(score.delta ?? 0).toFixed(2)}
                    </span>
                  </div>
                )}
                {score.incomplete && <p className="text-xs text-muted-foreground">Some analyzers failed.</p>}
              </div>
              <div className="space-y-1.5">
                <h3 className="font-medium">
                  Commits <Badge variant="secondary">{preview.planned_commits.length}</Badge>
                </h3>
                <ol className="space-y-1.5">
                  {preview.planned_commits.map((commit) => (
                    <li key={commit.suggestion_ids.join(',')} className="flex gap-1.5 text-xs">
                      <GitCommitHorizontal aria-hidden className="mt-0.5 size-3.5 shrink-0" />
                      <span>
                        <span className="font-mono">{commit.message.split('\n')[0]}</span>
                        <span className="block text-muted-foreground">{commit.paths.join(', ')}</span>
                      </span>
                    </li>
                  ))}
                </ol>
              </div>
            </div>
          </div>

          <div className="space-y-2">
            <h3 className="text-sm font-medium">
              Changes <span className="font-normal text-muted-foreground">({preview.files.length} files, full diff)</span>
            </h3>
            {preview.combined_diff ? (
              <UnifiedDiff diff={preview.combined_diff} className="max-h-[28rem]" />
            ) : (
              <p className="text-sm text-muted-foreground">No changes.</p>
            )}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3 border-t p-4">
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={reviewed}
              disabled={blocking.length > 0}
              onChange={(event) => setReviewed(event.target.checked)}
              className="size-4"
            />
            I reviewed these AI-generated changes
          </label>
          {confirm.isError && (
            <p role="alert" className="text-sm text-destructive">
              {confirm.error.message}
            </p>
          )}
          <div className="ml-auto flex gap-2">
            <Button variant="ghost" onClick={onClose} disabled={confirm.isPending}>
              Cancel
            </Button>
            <Button disabled={!canConfirm || confirm.isPending} onClick={() => confirm.mutate()}>
              <GitPullRequest aria-hidden />
              {confirm.isPending ? 'Creating…' : `Create pull request on ${preview.repo_full_name}`}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
