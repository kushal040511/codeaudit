import { Badge } from '@/components/ui/badge'
import type { Severity } from '@/lib/api'
import { cn } from '@/lib/utils'

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: 'border-transparent bg-red-600 text-white dark:bg-red-500',
  error: 'border-red-200 bg-red-50 text-red-700 dark:border-red-900 dark:bg-red-950 dark:text-red-300',
  warning:
    'border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-300',
  info: 'border-sky-200 bg-sky-50 text-sky-700 dark:border-sky-900 dark:bg-sky-950 dark:text-sky-300',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge variant="outline" className={cn('capitalize', SEVERITY_STYLES[severity])}>
      {severity}
    </Badge>
  )
}
