import { CircleCheck, CircleX, Clock, LoaderCircle, type LucideIcon } from 'lucide-react'
import type { ScanStatus } from '@/lib/api'
import { cn } from '@/lib/utils'

const STATUS_DISPLAY: Record<ScanStatus, { label: string; icon: LucideIcon; className: string; spin?: boolean }> = {
  queued: { label: 'Queued', icon: Clock, className: 'text-muted-foreground' },
  running: { label: 'Running', icon: LoaderCircle, className: 'text-blue-600 dark:text-blue-400', spin: true },
  completed: { label: 'Completed', icon: CircleCheck, className: 'text-emerald-600 dark:text-emerald-400' },
  failed: { label: 'Failed', icon: CircleX, className: 'text-destructive' },
}

export function StatusIndicator({ status }: { status: ScanStatus }) {
  const { label, icon: Icon, className, spin } = STATUS_DISPLAY[status]
  return (
    <span
      role="status"
      aria-live="polite"
      className={cn('inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-sm font-medium', className)}
    >
      <Icon aria-hidden className={cn('size-4', spin && 'animate-spin')} />
      {label}
    </span>
  )
}
