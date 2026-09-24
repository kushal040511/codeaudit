import { CircleCheck, CircleX, Clock, LoaderCircle, type LucideIcon, Sparkles, TriangleAlert } from 'lucide-react'
import type { ScanStatus } from '@/lib/api'
import { cn } from '@/lib/utils'

/**
 * Status runs on the same two-colour logic as everything else: navy while the
 * apparatus is working, orange only when something needs attention. Nothing here is
 * green — a finished scan is not good news, it is just a finished scan.
 */
const STATUS_DISPLAY: Record<ScanStatus, { label: string; icon: LucideIcon; className: string; spin?: boolean }> = {
  queued: { label: 'Queued', icon: Clock, className: 'text-muted-foreground' },
  running: { label: 'Running', icon: LoaderCircle, className: 'text-primary', spin: true },
  analysis_complete: { label: 'Analyzed', icon: CircleCheck, className: 'text-primary' },
  enriching: { label: 'Generating suggestions', icon: Sparkles, className: 'text-primary' },
  completed: { label: 'Completed', icon: CircleCheck, className: 'text-foreground' },
  partial: { label: 'Partial results', icon: TriangleAlert, className: 'text-ember dark:text-ember' },
  failed: { label: 'Failed', icon: CircleX, className: 'text-destructive' },
}

export function StatusIndicator({ status }: { status: ScanStatus }) {
  const { label, icon: Icon, className, spin } = STATUS_DISPLAY[status]
  return (
    <span
      role="status"
      aria-live="polite"
      className={cn('inline-flex items-center gap-1.5 rounded-sm border px-3 py-1 text-sm font-medium', className)}
    >
      <Icon aria-hidden className={cn('size-4', spin && 'animate-spin')} />
      {label}
    </span>
  )
}
