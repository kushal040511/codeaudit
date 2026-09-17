import type { RiskLevel } from '@/lib/api'

export const RISK_LABEL: Record<RiskLevel, string> = {
  low: 'Low risk signals',
  moderate: 'Some risk signals',
  high: 'Strong risk signals',
  very_high: 'Very strong risk signals',
}

export const RISK_COLOR: Record<RiskLevel, string> = {
  low: '#16a34a',
  moderate: '#d97706',
  high: '#ea580c',
  very_high: '#dc2626',
}
