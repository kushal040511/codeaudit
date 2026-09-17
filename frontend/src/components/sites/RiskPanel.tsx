import { CircleHelp, Info, TriangleAlert } from 'lucide-react'
import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { apiAsset, type Evidence, type EvidenceCategory, type SiteAnalysis, type SiteRisk } from '@/lib/api'
import { RISK_COLOR, RISK_LABEL } from '@/lib/risk'
import { cn } from '@/lib/utils'

const CATEGORY_LABEL: Record<EvidenceCategory, string> = {
  reputation: 'Reputation',
  visual: 'Visual',
  domain: 'Domain',
  content: 'Content',
  certificate: 'Certificate',
}
const SIDE_BY_SIDE_THRESHOLD = 0.84

export function RiskDisclaimer({ text }: { text: string }) {
  return (
    <div
      role="note"
      className="flex gap-3 rounded-lg border border-sky-300 bg-sky-50 p-3 text-sm text-sky-950 dark:border-sky-900 dark:bg-sky-950/40 dark:text-sky-100"
    >
      <Info aria-hidden className="mt-0.5 size-4 shrink-0" />
      <p>
        <strong>Heuristic risk assessment, not a verdict.</strong> {text}
      </p>
    </div>
  )
}

function Gauge({ score, level }: { score: number; level: SiteRisk['level'] }) {
  const radius = 80
  const circumference = Math.PI * radius
  const offset = circumference * (1 - score / 100)
  return (
    <svg viewBox="0 0 200 116" className="w-48" role="img" aria-label={`Risk score ${score} out of 100: ${RISK_LABEL[level]}`}>
      <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="currentColor" strokeOpacity={0.12} strokeWidth={16} strokeLinecap="round" />
      <path
        d="M 20 100 A 80 80 0 0 1 180 100"
        fill="none"
        stroke={RISK_COLOR[level]}
        strokeWidth={16}
        strokeLinecap="round"
        strokeDasharray={circumference}
        strokeDashoffset={offset}
      />
      <text x="100" y="92" textAnchor="middle" className="fill-current text-4xl font-semibold tabular-nums" style={{ fontSize: 40 }}>
        {score}
      </text>
      <text x="100" y="112" textAnchor="middle" className="fill-current opacity-60" style={{ fontSize: 11 }}>
        out of 100
      </text>
    </svg>
  )
}

function Points({ evidence }: { evidence: Evidence }) {
  if (evidence.status !== 'fired') {
    return <span className="w-12 shrink-0 text-right text-xs text-muted-foreground tabular-nums">{evidence.status === 'unavailable' ? 'n/a' : '0'}</span>
  }
  const positive = evidence.points > 0
  return (
    <span
      className={cn(
        'w-12 shrink-0 text-right font-mono text-sm font-semibold tabular-nums',
        positive ? 'text-red-700 dark:text-red-400' : 'text-emerald-700 dark:text-emerald-400',
      )}
    >
      {positive ? '+' : ''}
      {evidence.points}
    </span>
  )
}

function EvidenceRow({ evidence }: { evidence: Evidence }) {
  return (
    <li className={cn('flex items-start gap-3 py-2', evidence.status !== 'fired' && 'text-muted-foreground')}>
      <Points evidence={evidence} />
      <span className="w-20 shrink-0 text-xs tracking-wide uppercase opacity-70">{CATEGORY_LABEL[evidence.category]}</span>
      <span className="min-w-0 flex-1 text-sm break-words">{evidence.label}</span>
    </li>
  )
}

function VisualComparison({ analysis, risk }: { analysis: SiteAnalysis; risk: SiteRisk }) {
  const match = risk.visual_match
  if (!match || match.similarity < SIDE_BY_SIDE_THRESHOLD || !analysis.screenshot_url) return null
  return (
    <div className="space-y-2">
      <h3 className="text-sm font-medium">
        {Math.round(match.similarity * 100)}% visual similarity to the {match.brand_name} {match.page} page
      </h3>
      <div className="grid gap-3 md:grid-cols-2">
        <figure className="space-y-1">
          <img src={apiAsset(analysis.screenshot_url)} alt="Screenshot of the analyzed page" className="w-full rounded-md border" />
          <figcaption className="truncate font-mono text-xs text-muted-foreground">{analysis.final_url}</figcaption>
        </figure>
        <figure className="space-y-1">
          {match.reference_screenshot_url ? (
            <img
              src={apiAsset(match.reference_screenshot_url)}
              alt={`Reference screenshot of ${match.brand_name}`}
              className="w-full rounded-md border"
            />
          ) : (
            <div className="flex aspect-[1366/768] items-center justify-center rounded-md border text-xs text-muted-foreground">
              Reference screenshot not stored
            </div>
          )}
          <figcaption className="truncate font-mono text-xs text-muted-foreground">
            Reference: {match.reference_url}
          </figcaption>
        </figure>
      </div>
    </div>
  )
}

export function RiskPanel({ analysis, risk }: { analysis: SiteAnalysis; risk: SiteRisk }) {
  const [showAll, setShowAll] = useState(false)
  const fired = risk.evidence.filter((e) => e.status === 'fired')
  const other = risk.evidence.filter((e) => e.status !== 'fired')
  const unavailable = other.filter((e) => e.status === 'unavailable').length
  const risky = fired.filter((e) => e.points > 0).length
  const trust = fired.filter((e) => e.points < 0).length

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <TriangleAlert aria-hidden className="size-4" /> Phishing / clone risk signals
        </CardTitle>
        <CardDescription>Why this score: each signal that fired, and how many points it added.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        <RiskDisclaimer text={risk.disclaimer} />

        <div className="flex flex-col items-center gap-4 sm:flex-row sm:items-start">
          <div className="flex flex-col items-center" style={{ color: 'var(--foreground)' }}>
            <Gauge score={risk.score} level={risk.level} />
            <span className="text-sm font-medium" style={{ color: RISK_COLOR[risk.level] }}>
              {RISK_LABEL[risk.level]}
            </span>
          </div>
          <div className="min-w-0 flex-1 space-y-2 text-sm">
            <p className="font-medium">{risk.summary}</p>
            {risk.impersonated_brand && (
              <p className="text-muted-foreground">
                Signals point at impersonation of <strong className="text-foreground">{risk.impersonated_brand}</strong>.
              </p>
            )}
            <p className="text-xs text-muted-foreground">
              {risky} risk signal{risky === 1 ? '' : 's'}
              {trust > 0 && `, ${trust} trust signal${trust === 1 ? '' : 's'}`}, {unavailable} unavailable. Scoring
              model {risk.model_version}.
            </p>
          </div>
        </div>

        <VisualComparison analysis={analysis} risk={risk} />

        <div>
          <h3 className="mb-1 text-sm font-medium">Evidence</h3>
          {fired.length === 0 ? (
            <p className="text-sm text-muted-foreground">No risk signals fired.</p>
          ) : (
            <ul className="divide-y">{fired.map((e) => <EvidenceRow key={e.signal + e.label} evidence={e} />)}</ul>
          )}
          {other.length > 0 && (
            <>
              <button
                type="button"
                onClick={() => setShowAll((v) => !v)}
                className="mt-2 inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
              >
                <CircleHelp aria-hidden className="size-3.5" />
                {showAll ? 'Hide' : 'Show'} {other.length} checked signals that didn't add points
              </button>
              {showAll && <ul className="divide-y">{other.map((e) => <EvidenceRow key={e.signal + e.label} evidence={e} />)}</ul>}
            </>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
