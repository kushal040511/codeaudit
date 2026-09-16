import { cn } from '@/lib/utils'

function lineClass(line: string): string {
  if (line.startsWith('+++') || line.startsWith('---')) return 'font-semibold text-foreground'
  if (line.startsWith('@@')) return 'bg-sky-50 text-sky-800 dark:bg-sky-950/60 dark:text-sky-300'
  if (line.startsWith('+')) return 'bg-emerald-50 text-emerald-900 dark:bg-emerald-950/50 dark:text-emerald-200'
  if (line.startsWith('-')) return 'bg-red-50 text-red-900 dark:bg-red-950/50 dark:text-red-200'
  return 'text-muted-foreground'
}

/** The exact unified diff that will be committed, line by line. */
export function UnifiedDiff({ diff, className }: { diff: string; className?: string }) {
  const lines = diff.replace(/\n$/, '').split('\n')
  return (
    <div className={cn('overflow-auto rounded-md border bg-muted/20', className)}>
      <pre className="min-w-fit py-1 font-mono text-xs leading-5">
        {lines.map((line, index) => (
          // oxlint-disable-next-line react/no-array-index-key -- static text; lines can repeat
          <div key={index} className={cn('px-3 whitespace-pre', lineClass(line), line.startsWith('--- ') && index > 0 && 'mt-3 border-t pt-2')}>
            {line || ' '}
          </div>
        ))}
      </pre>
    </div>
  )
}
