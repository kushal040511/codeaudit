import { Badge } from '@/components/ui/badge'
import type { RiskLevel } from '@/lib/api'
import { RISK_LABEL } from '@/lib/risk'
import { cn } from '@/lib/utils'

const STYLE: Record<RiskLevel, string> = {
  low: 'border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950 dark:text-emerald-300',
  moderate: 'border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-300',
  high: 'border-orange-200 bg-orange-50 text-orange-800 dark:border-orange-900 dark:bg-orange-950 dark:text-orange-300',
  very_high: 'border-red-200 bg-red-50 text-red-800 dark:border-red-900 dark:bg-red-950 dark:text-red-300',
}

export function RiskBadge({ score, level }: { score: number; level: RiskLevel }) {
  return (
    <Badge variant="outline" className={cn('tabular-nums', STYLE[level])} title={RISK_LABEL[level]}>
      Risk {score}
    </Badge>
  )
}
