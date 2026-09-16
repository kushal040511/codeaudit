import type { AnalyzerRun } from '@/lib/api'

export const isFailedRun = (run: AnalyzerRun) => run.status === 'failed' || run.status === 'timed_out'

/** "Bandit timed out, Ruff failed" */
export function describeFailures(runs: AnalyzerRun[]): string {
  return runs
    .filter(isFailedRun)
    .map((run) => `${run.display_name} ${run.status === 'timed_out' ? 'timed out' : 'failed'}`)
    .join(', ')
}
