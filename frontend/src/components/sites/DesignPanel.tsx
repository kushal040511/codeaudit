import { useQuery } from '@tanstack/react-query'
import { Check, Copy, Download, Palette } from 'lucide-react'
import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { type ApiError, type DesignTokens, getSiteTokens, type TokenFormat } from '@/lib/api'

const FILENAMES: Record<TokenFormat, string> = { json: 'design-tokens.json', tailwind: 'tailwind.config.js', css: 'tokens.css' }
const MIME: Record<TokenFormat, string> = { json: 'application/json', tailwind: 'text/javascript', css: 'text/css' }

function readableOn(hex: string): string {
  const n = parseInt(hex.slice(1), 16)
  const [r, g, b] = [(n >> 16) & 255, (n >> 8) & 255, n & 255]
  return 0.299 * r + 0.587 * g + 0.114 * b > 150 ? '#111827' : '#ffffff'
}

function Swatch({ name, hex, detail }: { name: string; hex: string; detail?: string }) {
  return (
    <div className="overflow-hidden rounded-lg border">
      <div className="flex h-16 items-end p-2 font-mono text-xs" style={{ background: hex, color: readableOn(hex) }}>
        {hex}
      </div>
      <div className="px-2 py-1.5 text-xs">
        <div className="font-medium capitalize">{name.replace('_', ' ')}</div>
        {detail && <div className="text-muted-foreground">{detail}</div>}
      </div>
    </div>
  )
}

function CodeOutputs({ analysisId }: { analysisId: string }) {
  const [format, setFormat] = useState<TokenFormat>('tailwind')
  const [copied, setCopied] = useState(false)
  const code = useQuery<string, ApiError>({
    queryKey: ['sites', analysisId, 'tokens', format],
    queryFn: () => getSiteTokens(analysisId, format),
    staleTime: Infinity,
  })

  function download() {
    if (!code.data) return
    const url = URL.createObjectURL(new Blob([code.data], { type: MIME[format] }))
    const link = document.createElement('a')
    link.href = url
    link.download = FILENAMES[format]
    link.click()
    URL.revokeObjectURL(url)
  }

  return (
    <Tabs value={format} onValueChange={(value) => { setFormat(value as TokenFormat); setCopied(false) }}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <TabsList>
          <TabsTrigger value="tailwind">Tailwind</TabsTrigger>
          <TabsTrigger value="css">CSS</TabsTrigger>
          <TabsTrigger value="json">JSON</TabsTrigger>
        </TabsList>
        <div className="flex gap-2">
          <Button
            size="sm"
            variant="outline"
            disabled={!code.data}
            onClick={() => code.data && void navigator.clipboard.writeText(code.data).then(() => setCopied(true))}
          >
            {copied ? <Check aria-hidden /> : <Copy aria-hidden />} {copied ? 'Copied' : 'Copy'}
          </Button>
          <Button size="sm" variant="outline" disabled={!code.data} onClick={download}>
            <Download aria-hidden /> {FILENAMES[format]}
          </Button>
        </div>
      </div>
      {(['tailwind', 'css', 'json'] as const).map((value) => (
        <TabsContent key={value} value={value}>
          {code.isError ? (
            <p role="alert" className="text-sm text-destructive">{code.error.message}</p>
          ) : (
            <pre className="max-h-96 overflow-auto rounded-md border bg-muted/30 p-3 font-mono text-xs leading-5">
              {code.data ?? 'Loading…'}
            </pre>
          )}
        </TabsContent>
      ))}
    </Tabs>
  )
}

export function DesignPanel({ analysisId, tokens, notes }: { analysisId: string; tokens: DesignTokens; notes: string[] }) {
  const roles = Object.entries(tokens.colors.roles)
  const typo = tokens.typography
  const bodyStack = typo.families.body?.stack
  const headingStack = typo.families.heading?.stack ?? bodyStack
  const maxSpace = Math.max(...tokens.spacing.scale, 1)

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Palette aria-hidden className="size-4" /> Design tokens
        </CardTitle>
        <CardDescription>
          From the page's computed CSS ({tokens.elements_sampled.toLocaleString()} elements). Fonts preview with your
          installed fallbacks.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {notes.length > 0 && (
          <ul className="space-y-1 text-xs text-muted-foreground">
            {notes.map((note) => <li key={note}>{note}</li>)}
          </ul>
        )}

        <section className="space-y-2">
          <h3 className="text-sm font-medium">Color roles</h3>
          {roles.length === 0 ? (
            <p className="text-sm text-muted-foreground">No colors captured.</p>
          ) : (
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              {roles.map(([name, role]) => (
                <Swatch
                  key={name}
                  name={name}
                  hex={role!.hex}
                  detail={role!.contrast_on_background ? `${role!.contrast_on_background}:1 on background` : `${Math.round(role!.usage * 100)}% of usage`}
                />
              ))}
            </div>
          )}
          {tokens.colors.palette.length > 0 && (
            <div className="flex flex-wrap gap-1 pt-1" aria-label="Full palette">
              {tokens.colors.palette.map((entry) => (
                <span
                  key={entry.hex}
                  title={`${entry.hex}, ${Math.round(entry.usage * 1000) / 10}%`}
                  className="size-7 rounded border"
                  style={{ background: entry.hex }}
                />
              ))}
            </div>
          )}
        </section>

        <section className="space-y-2">
          <h3 className="text-sm font-medium">
            Typography
            <span className="ml-2 font-normal text-muted-foreground">
              {typo.families.heading?.name && typo.families.heading.name !== typo.families.body?.name
                ? `${typo.families.heading.name} / ${typo.families.body?.name}`
                : typo.families.body?.name}
            </span>
          </h3>
          <div className="space-y-1 overflow-hidden rounded-md border p-3">
            {[...typo.sizes].reverse().map((size) => (
              <div key={size.px} className="flex items-baseline gap-3">
                <span className="w-16 shrink-0 font-mono text-xs text-muted-foreground">{size.px}px</span>
                <span
                  className="truncate"
                  style={{
                    fontSize: Math.min(size.px, 64),
                    lineHeight: size.line_height && size.line_height !== 'normal' ? size.line_height : undefined,
                    fontFamily: (size.px >= 28 ? headingStack : bodyStack) ?? undefined,
                  }}
                >
                  The quick brown fox
                </span>
              </div>
            ))}
            {typo.sizes.length === 0 && <p className="text-sm text-muted-foreground">No text captured.</p>}
          </div>
        </section>

        <div className="grid gap-6 md:grid-cols-2">
          <section className="space-y-2">
            <h3 className="text-sm font-medium">
              Spacing{' '}
              {tokens.spacing.base_px && (
                <span className="font-normal text-muted-foreground">
                  {tokens.spacing.base_px}px grid ({Math.round(tokens.spacing.coverage * 100)}% of values fit)
                </span>
              )}
            </h3>
            <div className="space-y-1">
              {tokens.spacing.scale.map((px) => (
                <div key={px} className="flex items-center gap-2">
                  <span className="w-12 shrink-0 font-mono text-xs text-muted-foreground">{px}px</span>
                  <span className="h-3 rounded-sm bg-primary/70" style={{ width: `${Math.max(2, (px / maxSpace) * 100)}%` }} />
                </div>
              ))}
            </div>
          </section>
          <section className="space-y-2">
            <h3 className="text-sm font-medium">Radii and shadows</h3>
            <div className="flex flex-wrap gap-3">
              {tokens.radii.map((radius) => (
                <div key={radius.value} className="text-center">
                  <div className="size-14 border-2 border-foreground/40 bg-muted" style={{ borderRadius: radius.value === '9999px' ? 9999 : radius.value }} />
                  <div className="mt-1 font-mono text-xs text-muted-foreground">{radius.value === '9999px' ? 'full' : radius.value}</div>
                </div>
              ))}
              {tokens.shadows.slice(0, 3).map((shadow, index) => (
                <div key={shadow.value} className="text-center">
                  <div className="size-14 rounded-md bg-background" style={{ boxShadow: shadow.value }} />
                  <div className="mt-1 font-mono text-xs text-muted-foreground">shadow {index + 1}</div>
                </div>
              ))}
            </div>
          </section>
        </div>

        {tokens.vision && (
          <section className="space-y-2 text-sm">
            <h3 className="font-medium">Style (vision model)</h3>
            <p>{tokens.vision.style}</p>
            <p className="text-muted-foreground"><span className="font-medium text-foreground">Layout:</span> {tokens.vision.layout}</p>
            <p className="text-muted-foreground"><span className="font-medium text-foreground">Hierarchy:</span> {tokens.vision.visual_hierarchy}</p>
            {tokens.dropped_colors.length > 0 && (
              <p className="text-xs text-muted-foreground">
                Dropped {tokens.dropped_colors.length} color{tokens.dropped_colors.length === 1 ? '' : 's'} the model named
                but the page's CSS doesn't use: {tokens.dropped_colors.map((c) => c.hex).join(', ')}.
              </p>
            )}
          </section>
        )}

        <section className="space-y-2">
          <h3 className="text-sm font-medium">Code</h3>
          <CodeOutputs analysisId={analysisId} />
        </section>

        <section className="space-y-2">
          <h3 className="text-sm font-medium">Prompt for recreating this aesthetic</h3>
          <pre className="rounded-md border bg-muted/30 p-3 text-xs whitespace-pre-wrap">{tokens.prompt}</pre>
        </section>
      </CardContent>
    </Card>
  )
}
