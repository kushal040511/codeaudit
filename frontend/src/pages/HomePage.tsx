import { useMutation, useQuery } from '@tanstack/react-query'
import { type FormEvent, useId, useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { analyzeSite, type ApiError, createRepoScan, getHealth } from '@/lib/api'
import { cn } from '@/lib/utils'

type Target = { kind: 'repository'; url: string } | { kind: 'website'; url: string } | { kind: 'none' }

/** GitHub repository links go to a code scan; any other web address to the Site Analyzer. */
function classify(raw: string): Target {
  const text = raw.trim()
  if (!text) return { kind: 'none' }
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `https://${text}`
  let url: URL
  try {
    url = new URL(withScheme)
  } catch {
    return { kind: 'none' }
  }
  if (!url.hostname.includes('.')) return { kind: 'none' }
  const host = url.hostname.replace(/^www\./, '')
  const segments = url.pathname.split('/').filter(Boolean)
  if (host === 'github.com' && segments.length >= 2) return { kind: 'repository', url: withScheme }
  return { kind: 'website', url: withScheme }
}

const EXAMPLES = [
  { label: 'a GitHub repository', value: 'github.com/pallets/itsdangerous' },
  { label: 'a website', value: 'stripe.com' },
]

function AuditBox() {
  const inputId = useId()
  const navigate = useNavigate()
  const [value, setValue] = useState('')
  const target = classify(value)

  const start = useMutation<string, ApiError, Target>({
    mutationFn: async (t) => {
      if (t.kind === 'repository') return `/scans/${(await createRepoScan(t.url)).scan_id}`
      if (t.kind === 'website') return `/sites/${(await analyzeSite(t.url)).analysis_id}`
      throw new Error('Paste a GitHub repository or a website address.')
    },
    onSuccess: (path) => navigate(path),
  })

  function submit(event: FormEvent) {
    event.preventDefault()
    if (target.kind !== 'none' && !start.isPending) start.mutate(target)
  }

  const action = target.kind === 'repository' ? 'Scan repository' : target.kind === 'website' ? 'Analyze website' : 'Paste a link'
  const hint =
    target.kind === 'repository'
      ? 'Security findings, vulnerable dependencies and architecture problems, with a score.'
      : target.kind === 'website'
        ? 'Phishing and clone risk signals, plus the site’s design tokens.'
        : 'A GitHub repository gets a code audit. Any other address gets the Site Analyzer.'

  return (
    <form onSubmit={submit} className="w-full max-w-2xl" data-no-pulse>
      <label htmlFor={inputId} className="sr-only">
        GitHub repository or website address
      </label>
      <div
        className={cn(
          'flex flex-col gap-2 rounded-lg border-2 bg-[var(--sheet)] p-2 shadow-[0_1px_0_var(--gridline),0_18px_40px_-24px_color-mix(in_oklab,var(--ink)_45%,transparent)] transition-colors sm:flex-row',
          target.kind === 'repository' && 'border-[var(--ink)]',
          target.kind === 'website' && 'border-[var(--blueprint)]',
          target.kind === 'none' && 'border-[var(--input)]',
        )}
      >
        <input
          id={inputId}
          value={value}
          onChange={(event) => {
            setValue(event.target.value)
            start.reset()
          }}
          placeholder="github.com/owner/repo or example.com"
          autoComplete="off"
          spellCheck={false}
          inputMode="url"
          className="h-12 min-w-0 flex-1 bg-transparent px-3 font-mono text-[15px] text-foreground outline-none placeholder:text-[var(--graphite)]/70"
        />
        <button
          type="submit"
          disabled={target.kind === 'none' || start.isPending}
          className={cn(
            'h-12 shrink-0 rounded-md px-5 font-heading text-base font-semibold [font-stretch:85%] text-[var(--sheet)] transition-[background-color,transform] active:translate-y-px disabled:cursor-not-allowed',
            target.kind === 'repository' ? 'bg-[var(--ink)] hover:bg-[#1c3753]' : 'bg-[var(--blueprint)] hover:bg-[#184c88]',
            target.kind === 'none' && 'bg-[var(--graphite)]/40 text-[var(--sheet)]',
          )}
        >
          {start.isPending ? (target.kind === 'repository' ? 'Starting scan…' : 'Starting analysis…') : action}
        </button>
      </div>
      <p aria-live="polite" className="mt-3 text-sm text-muted-foreground">
        {start.isError ? <span className="text-[var(--pencil)]">{start.error.message}</span> : hint}
      </p>
      {!value && (
        <p className="mt-2 text-sm text-muted-foreground">
          Try{' '}
          {EXAMPLES.map((example, index) => (
            <span key={example.value}>
              {index > 0 && ' or '}
              <button
                type="button"
                onClick={() => setValue(example.value)}
                className="rounded font-mono text-[13px] text-foreground underline decoration-[var(--gridline)] decoration-2 underline-offset-4 hover:decoration-[var(--blueprint)]"
                title={`Fill in ${example.label}`}
              >
                {example.value}
              </button>
            </span>
          ))}
          , or{' '}
          <Link to="/upload" className="underline decoration-[var(--gridline)] decoration-2 underline-offset-4 hover:decoration-[var(--blueprint)]">
            upload a .zip
          </Link>
          .
        </p>
      )}
    </form>
  )
}

function ServiceStatus() {
  const health = useQuery({ queryKey: ['health'], queryFn: getHealth, refetchInterval: 15_000 })
  const checks = health.data ? Object.entries(health.data.checks) : []
  const failing = checks.filter(([, check]) => check.status !== 'ok')
  const state = health.isError ? 'down' : !health.data ? 'checking' : failing.length ? 'degraded' : 'ok'
  return (
    <details className="group text-sm text-muted-foreground">
      <summary className="inline-flex cursor-pointer list-none items-center gap-2 rounded px-1 hover:text-foreground">
        <span
          aria-hidden
          className={cn(
            'size-2 rounded-full',
            state === 'ok' && 'bg-emerald-600',
            state === 'checking' && 'bg-[var(--graphite)]',
            (state === 'degraded' || state === 'down') && 'bg-[var(--pencil)]',
          )}
        />
        {state === 'ok' && `All services running (API v${health.data?.version})`}
        {state === 'checking' && 'Checking services…'}
        {state === 'degraded' && `${failing.map(([name]) => name).join(', ')} unavailable`}
        {state === 'down' && 'The API is unreachable'}
      </summary>
      <ul className="mt-2 grid max-w-md grid-cols-2 gap-x-6 gap-y-1 pl-5">
        {checks.map(([name, check]) => (
          <li key={name} className="flex justify-between gap-3">
            <span className="capitalize">{name}</span>
            <span className={check.status === 'ok' ? '' : 'text-[var(--pencil)]'}>
              {check.status === 'ok' ? `${check.latency_ms} ms` : (check.detail ?? 'error')}
            </span>
          </li>
        ))}
      </ul>
    </details>
  )
}

export function HomePage() {
  return (
    <div className="flex min-h-[calc(100svh-10rem)] flex-col justify-between gap-16">
      <section className="flex flex-col items-start gap-8 pt-[8vh]">
        <h1 className="max-w-[16ch] font-heading text-[clamp(2.75rem,7vw,5.25rem)] leading-[0.95] font-semibold text-[var(--ink)] [font-stretch:68%] [letter-spacing:-0.02em]">
          Find what’s wrong in a codebase or a website.
        </h1>
        <p className="max-w-[58ch] text-lg text-[var(--graphite)]">
          CodeAudit reads your repository the way a reviewer would: security issues, risky dependencies and tangled
          architecture, each with the fix and its effect on the score. Give it a website instead and it checks for
          signs of a phishing clone and pulls out the design system.
        </p>
        <AuditBox />
        <p className="hidden text-sm text-muted-foreground [@media(pointer:fine)]:block">
          The lines behind this page are a module graph. Move your pointer to trace imports; click anywhere empty to run a
          scan across it.
        </p>
      </section>
      <footer className="flex flex-wrap items-end justify-between gap-4 border-t border-border/70 pt-4">
        <ServiceStatus />
        <p className="text-sm text-muted-foreground">Websites open in an isolated browser. Repositories are only changed if you confirm a pull request.</p>
      </footer>
    </div>
  )
}
