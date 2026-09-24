import { useQuery } from '@tanstack/react-query'
import { TriangleAlert } from 'lucide-react'
import { useEffect, useState } from 'react'
import { type ApiError, getScore, type Scan, type ScanScore } from '@/lib/api'
import { cn } from '@/lib/utils'

/** Mirrors GRADES in backend/app/services/scoring/rubric.py. */
const BANDS = [
  { letter: 'F', from: 0 },
  { letter: 'D', from: 55 },
  { letter: 'C', from: 70 },
  { letter: 'B', from: 80 },
  { letter: 'A', from: 90 },
] as const

const TICKS = [0, 55, 70, 80, 90, 100]

function nextBandUp(score: number): { letter: string; gap: number } | null {
  const above = BANDS.find((band) => band.from > score)
  return above ? { letter: above.letter, gap: above.from - score } : null
}

/**
 * The scan's verdict, read against the grade bands rather than shown as a bare number.
 * Where a score sits inside its band is information the number alone loses: a 74.6 is a
 * C, but it is a C five points below a B. The four pillars share that same 0–100 axis,
 * so the one dragging the average is found by eye, without a label saying so.
 */
export function ScoreCard({ scan }: { scan: Scan }) {
  const score = useQuery<ScanScore, ApiError>({
    queryKey: ['scan', scan.id, 'score', scan.score?.overall],
    queryFn: () => getScore(scan.id),
    enabled: scan.score !== null,
  })

  // The one orchestrated moment: bars draw from zero once, on arrival.
  const [drawn, setDrawn] = useState(false)
  useEffect(() => {
    const id = requestAnimationFrame(() => setDrawn(true))
    return () => cancelAnimationFrame(id)
  }, [])

  if (scan.score === null) return null
  const data = score.data
  const overall = scan.score.overall
  const next = overall === null ? null : nextBandUp(overall)

  const scored = (data?.categories ?? []).filter((category) => category.score !== null)
  const weakest = scored.reduce<(typeof scored)[number] | null>(
    (low, category) => (low === null || category.score! < low.score! ? category : low),
    null,
  )

  return (
    <section
      aria-labelledby="score-heading"
      className="rounded-sm bg-steel text-[#e8eef0] [--track:color-mix(in_oklab,var(--haze)_22%,transparent)]"
    >
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-b border-[color-mix(in_oklab,var(--haze)_16%,transparent)] px-6 py-3 font-mono text-xs text-mist">
        <h2 id="score-heading" className="font-sans text-xs tracking-normal text-mist">
          Deterministic score
        </h2>
        <span>rubric v{scan.score.rubric_version}</span>
        <span className="text-[#7d8f9c]">severity-weighted, normalised by codebase size</span>
        <span className="ml-auto text-[#7d8f9c]">AI suggestions never change it</span>
      </div>

      <div className="grid gap-8 px-6 py-7 lg:grid-cols-[minmax(0,14rem)_minmax(0,1fr)] lg:gap-12">
        <div>
          <div className="flex items-baseline gap-4">
            <span className="font-sans text-[5rem] leading-[0.85] font-extralight tabular-nums">
              {overall === null ? '—' : overall.toFixed(1)}
            </span>
            <span
              aria-label={scan.score.grade ? `Grade ${scan.score.grade}` : 'Not graded'}
              className="font-sans text-4xl leading-none font-light text-mist"
            >
              {scan.score.grade ?? '–'}
            </span>
          </div>
          <p className="mt-3 text-sm text-[#a9bcc6]">
            {next === null
              ? 'Top band.'
              : `${next.gap.toFixed(1)} points below a ${next.letter}.`}
          </p>
          {scan.score.incomplete && (
            <p className="mt-3 flex gap-1.5 text-sm text-ember">
              <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0" />
              <span>
                Incomplete: {data?.incomplete_reasons.join('; ') ?? 'an analyzer failed'}. Not comparable with complete
                scores.
              </span>
            </p>
          )}
        </div>

        <div>
          {/* The band axis. Read as one sentence by a screen reader; drawn for everyone else. */}
          <p className="sr-only">
            {overall === null
              ? 'No overall score.'
              : `Scores ${overall.toFixed(1)} of 100. Grade bands: F below 55, D from 55, C from 70, B from 80, A from 90.`}
          </p>
          <div aria-hidden className="relative h-14">
            <div className="absolute inset-x-0 top-5 h-px bg-[color-mix(in_oklab,var(--haze)_28%,transparent)]" />
            {TICKS.map((tick) => (
              <div key={tick} className="absolute top-2 -translate-x-1/2" style={{ left: `${tick}%` }}>
                <div className="mx-auto h-3 w-px bg-[color-mix(in_oklab,var(--haze)_40%,transparent)]" />
                <div className="mt-1.5 font-mono text-[0.6875rem] text-[#7d8f9c] tabular-nums">{tick}</div>
              </div>
            ))}
            {BANDS.map((band, index) => {
              const to = BANDS[index + 1]?.from ?? 100
              return (
                <div
                  key={band.letter}
                  className="absolute top-0 text-center font-sans text-xs text-[#7d8f9c]"
                  style={{ left: `${band.from}%`, width: `${to - band.from}%` }}
                >
                  {band.letter}
                </div>
              )
            })}
            {overall !== null && (
              <div
                className="absolute top-3.5 -translate-x-1/2 transition-[left] duration-700 ease-instrument"
                style={{ left: `${drawn ? overall : 0}%` }}
              >
                <div className="size-3 rotate-45 border-2 border-flare bg-steel" />
              </div>
            )}
          </div>

          {data && (
            <dl className="mt-6 space-y-3.5">
              {data.categories.map((category) => {
                const isWeakest = weakest !== null && category.category === weakest.category
                return (
                  <div key={category.category} className="grid grid-cols-[8.5rem_minmax(0,1fr)_3.25rem] items-center gap-x-3">
                    <dt className="truncate text-sm text-[#a9bcc6]" title={category.label}>
                      {category.label}
                      <span className="ml-1.5 font-mono text-[0.6875rem] text-[#7d8f9c]">
                        {Math.round(category.weight * 100)}%
                      </span>
                    </dt>
                    {category.score === null ? (
                      <>
                        <p className="text-xs text-[#7d8f9c]">Excluded: {category.excluded_reason}</p>
                        <dd className="text-right font-mono text-sm text-[#7d8f9c]">—</dd>
                      </>
                    ) : (
                      <>
                        <div className="h-1.5 bg-[var(--track)]">
                          <div
                            className={cn(
                              'h-full transition-[width] duration-700 ease-instrument',
                              isWeakest ? 'bg-flare' : 'bg-mist',
                            )}
                            style={{ width: `${drawn ? category.score : 0}%` }}
                          />
                        </div>
                        <dd
                          className={cn(
                            'text-right font-mono text-sm tabular-nums',
                            isWeakest ? 'text-flare' : 'text-[#e8eef0]',
                          )}
                        >
                          {category.score.toFixed(0)}
                        </dd>
                      </>
                    )}
                    {category.score !== null && (
                      <div className="col-start-2 col-end-4 space-y-0.5">
                        {category.rationale.length > 0 && (
                          <p className="truncate text-xs text-[#7d8f9c]" title={category.rationale.join('\n')}>
                            Worst: {category.rationale[0]}
                          </p>
                        )}
                        {(category.deductions ?? []).map((line) => (
                          <p key={line.label} className="flex justify-between gap-2 text-xs text-[#7d8f9c]">
                            <span className="truncate" title={line.label}>
                              {line.label}
                              {line.signal_score != null && <> · signal {Math.round(line.signal_score * 100)}%</>}
                            </span>
                            {line.signal !== null && (
                              <span className="font-mono tabular-nums">−{line.points.toFixed(1)}</span>
                            )}
                          </p>
                        ))}
                      </div>
                    )}
                  </div>
                )
              })}
            </dl>
          )}
        </div>
      </div>
    </section>
  )
}
