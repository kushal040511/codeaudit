import type { Severity } from '@/lib/api'
import { cn } from '@/lib/utils'

/**
 * Severity reads as a rule, not a pill. The hue runs hot to cool in severity order —
 * orange is the only warm colour in the interface and it means exactly this. Rule
 * weight carries the same order, so severity never depends on colour alone, and the
 * label keeps full text contrast instead of being tinted down to meet it.
 */
export const SEVERITY_RULE: Record<Severity, string> = {
  critical: 'bg-flare',
  error: 'bg-ember',
  warning: 'bg-mist',
  info: 'bg-haze',
}

/** The same ramp as CSS values, for rules drawn on an element's own border. */
export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: 'var(--flare)',
  error: 'var(--ember)',
  warning: 'var(--mist)',
  info: 'var(--haze)',
}

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 3,
  error: 2,
  warning: 2,
  info: 2,
}

const SEVERITY_WIDTH: Record<Severity, string> = {
  critical: 'w-[3px]',
  error: 'w-[2px]',
  warning: 'w-[2px]',
  info: 'w-[2px]',
}

/** `rule` off where the row already carries the rule on its own edge. */
export function SeverityBadge({ severity, rule = true }: { severity: Severity; rule?: boolean }) {
  return (
    <span className="inline-flex items-stretch gap-2">
      {rule && (
        <span aria-hidden className={cn('shrink-0 self-stretch', SEVERITY_RULE[severity], SEVERITY_WIDTH[severity])} />
      )}
      <span
        className={cn(
          'capitalize',
          severity === 'critical' ? 'font-medium text-foreground' : 'text-muted-foreground',
        )}
      >
        {severity}
      </span>
    </span>
  )
}
