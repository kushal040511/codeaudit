import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, CircleX, Copy, LoaderCircle, RefreshCw, ShieldCheck, Sparkles, TriangleAlert } from 'lucide-react'
import { lazy, Suspense, useState } from 'react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { type ApiError, type Finding, type FixSuggestion, getFix, regenerateFix, type ValidationStatus } from '@/lib/api'
import { cn } from '@/lib/utils'

// Monaco is large; load it only when a verified diff is shown.
const PatchDiff = lazy(() => import('@/components/fixes/PatchDiff'))

const INVALID_REASON: Record<Exclude<ValidationStatus, 'valid'>, string> = {
  failed_to_apply: "This patch does not apply to the scanned code, so it can't be used as-is.",
  syntax_error: 'This patch applies, but the resulting file no longer parses.',
  no_patch: 'No code change was proposed for this finding.',
  not_validated: 'This suggestion has not been validated.',
}

const CONFIDENCE_STYLE: Record<NonNullable<FixSuggestion['confidence']>, string> = {
  high: 'border-emerald-300 bg-emerald-50 text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950 dark:text-emerald-300',
  medium: 'border-amber-300 bg-amber-50 text-amber-800 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-300',
  low: 'border-slate-300 bg-slate-50 text-slate-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300',
}

function CopyPatchButton({ patch }: { patch: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <Button
      size="sm"
      variant="outline"
      onClick={async () => {
        await navigator.clipboard.writeText(patch)
        setCopied(true)
        window.setTimeout(() => setCopied(false), 2000)
      }}
    >
      {copied ? <Check /> : <Copy />} {copied ? 'Copied' : 'Copy patch'}
    </Button>
  )
}

function Suggestion({ fix }: { fix: FixSuggestion }) {
  const [showRejected, setShowRejected] = useState(false)
  const verified = fix.patch_verified && fix.patch
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        {verified ? (
          <Badge className="gap-1 border-emerald-300 bg-emerald-50 text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950 dark:text-emerald-300" variant="outline">
            <ShieldCheck /> Patch verified
          </Badge>
        ) : fix.validation_status === 'no_patch' ? (
          <Badge variant="outline">No change proposed</Badge>
        ) : (
          <Badge variant="destructive" className="gap-1">
            <CircleX /> Patch not verified
          </Badge>
        )}
        {fix.confidence && (
          <Badge variant="outline" className={cn('capitalize', CONFIDENCE_STYLE[fix.confidence])}>
            {fix.confidence} confidence
          </Badge>
        )}
        {fix.shared_with_finding_ids.length > 0 && (
          <Badge variant="secondary">Also fixes {fix.shared_with_finding_ids.length} related finding(s)</Badge>
        )}
        <span className="text-xs text-muted-foreground">
          v{fix.version} · {fix.model}
        </span>
      </div>

      {fix.breaking_risk === 'high' && (
        <p role="alert" className="flex gap-2 rounded-md border border-red-300 bg-red-50 p-3 text-sm text-red-900 dark:border-red-900 dark:bg-red-950 dark:text-red-200">
          <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0" />
          High breaking risk: this change may alter behaviour for existing callers. Review and test before applying.
        </p>
      )}
      {fix.breaking_risk === 'low' && (
        <p className="text-sm text-amber-700 dark:text-amber-400">Low breaking risk: check callers of the changed code.</p>
      )}

      {fix.explanation && (
        <section className="space-y-1">
          <h4 className="text-xs font-semibold text-muted-foreground uppercase">Why this is a problem</h4>
          <p className="text-sm whitespace-pre-line">{fix.explanation}</p>
        </section>
      )}

      {verified ? (
        <section className="space-y-2">
          <div className="flex items-center justify-between gap-2">
            <h4 className="text-xs font-semibold text-muted-foreground uppercase">Proposed change</h4>
            <CopyPatchButton patch={fix.patch!} />
          </div>
          <Suspense fallback={<p className="text-sm text-muted-foreground">Loading diff…</p>}>
            {fix.file_changes.map((change) => (
              <PatchDiff key={change.path} change={change} />
            ))}
          </Suspense>
          <p className="text-xs text-muted-foreground">
            Verified: applies cleanly to the scanned code and the result parses. It was not compiled or tested.
          </p>
        </section>
      ) : (
        fix.validation_status !== 'no_patch' && (
          <section role="alert" className="space-y-2 rounded-md border border-red-300 bg-red-50/60 p-3 dark:border-red-900 dark:bg-red-950/40">
            <p className="text-sm font-medium text-red-900 dark:text-red-200">
              {INVALID_REASON[fix.validation_status as Exclude<ValidationStatus, 'valid'>]}
            </p>
            {fix.validation_detail && (
              <pre className="overflow-x-auto font-mono text-xs whitespace-pre-wrap text-red-800 dark:text-red-300">
                {fix.validation_detail}
              </pre>
            )}
            {fix.rejected_patch && (
              <div>
                <Button size="sm" variant="ghost" onClick={() => setShowRejected((v) => !v)}>
                  {showRejected ? 'Hide' : 'Show'} the unverified patch anyway
                </Button>
                {showRejected && (
                  <pre className="mt-2 max-h-72 overflow-auto rounded border bg-background p-2 font-mono text-xs opacity-80">
                    {fix.rejected_patch}
                  </pre>
                )}
              </div>
            )}
          </section>
        )
      )}

      {fix.test_suggestion && (
        <section className="space-y-1">
          <h4 className="text-xs font-semibold text-muted-foreground uppercase">Regression test</h4>
          <p className="text-sm whitespace-pre-line">{fix.test_suggestion}</p>
        </section>
      )}
    </div>
  )
}

export function FixPanel({ scanId, finding }: { scanId: string; finding: Finding }) {
  const queryClient = useQueryClient()
  const [hint, setHint] = useState('')
  const fixKey = ['scan', scanId, 'fix', finding.id]

  const fix = useQuery<FixSuggestion, ApiError>({
    queryKey: fixKey,
    queryFn: () => getFix(scanId, finding.id),
    retry: (count, error) => error.status !== 404 && count < 2,
    refetchInterval: (query) => (query.state.data?.status === 'generating' ? 2000 : false),
  })

  const regenerate = useMutation<FixSuggestion, ApiError, string>({
    mutationFn: (userHint) => regenerateFix(scanId, finding.id, userHint),
    onSuccess: (data) => {
      queryClient.setQueryData(fixKey, data)
      setHint('')
      void queryClient.invalidateQueries({ queryKey: ['scan', scanId] })
    },
  })

  if (finding.analyzer === 'architecture') {
    return (
      <p className="text-sm text-muted-foreground">
        Structural issues span several modules; see the Architecture tab and its AI review for refactoring steps.
      </p>
    )
  }

  const notFound = fix.isError && fix.error.status === 404
  const generating = fix.data?.status === 'generating' || regenerate.isPending

  return (
    <div className="space-y-4">
      {fix.isPending ? (
        <p className="text-sm text-muted-foreground">Loading suggestion…</p>
      ) : notFound ? (
        <p className="text-sm text-muted-foreground">
          No AI fix suggestion for this finding. Suggestions are generated automatically for the highest-priority
          findings; you can request one below.
        </p>
      ) : fix.isError ? (
        <p className="text-sm text-destructive">Could not load the suggestion: {fix.error.message}</p>
      ) : generating ? (
        <p className="flex items-center gap-2 text-sm text-muted-foreground">
          <LoaderCircle className="size-4 animate-spin" /> Generating a fix suggestion…
        </p>
      ) : fix.data.status === 'failed' ? (
        <p role="alert" className="text-sm text-destructive">
          No suggestion could be generated: {fix.data.error_message}
        </p>
      ) : (
        <Suggestion fix={fix.data} />
      )}

      <form
        className="space-y-2 border-t pt-4"
        onSubmit={(event) => {
          event.preventDefault()
          regenerate.mutate(hint)
        }}
      >
        <label htmlFor="fix-hint" className="text-xs font-semibold text-muted-foreground uppercase">
          {notFound ? 'Generate a suggestion' : 'Regenerate'}
        </label>
        <textarea
          id="fix-hint"
          value={hint}
          onChange={(event) => setHint(event.target.value)}
          maxLength={2000}
          rows={2}
          placeholder="Optional hint, e.g. “keep the public API unchanged” or “use parameterized queries”"
          className="w-full rounded-md border bg-background px-2 py-1.5 text-sm"
        />
        <div className="flex items-center gap-2">
          <Button type="submit" size="sm" disabled={generating}>
            {notFound ? <Sparkles /> : <RefreshCw />} {notFound ? 'Generate' : 'Regenerate'}
          </Button>
          {regenerate.isError && <span className="text-sm text-destructive">{regenerate.error.message}</span>}
        </div>
      </form>
    </div>
  )
}
