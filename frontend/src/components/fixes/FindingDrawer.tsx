import { SeverityBadge } from '@/components/scans/SeverityBadge'
import { FixPanel } from '@/components/fixes/FixPanel'
import { Sheet, SheetContent, SheetDescription, SheetTitle } from '@/components/ui/sheet'
import type { Finding } from '@/lib/api'

type Props = {
  scanId: string
  finding: Finding | null
  displayName: (analyzer: string) => string
  onClose: () => void
}

export function FindingDrawer({ scanId, finding, displayName, onClose }: Props) {
  return (
    <Sheet open={finding !== null} onOpenChange={(open) => !open && onClose()}>
      <SheetContent>
        {finding && (
          <div className="flex h-full flex-col overflow-y-auto">
            <div className="space-y-2 border-b p-4">
              <div className="flex items-center gap-2">
                <SeverityBadge severity={finding.severity} />
                <span className="text-xs text-muted-foreground">
                  {displayName(finding.analyzer)} · <span className="font-mono">{finding.rule_id}</span>
                </span>
              </div>
              <SheetTitle>{finding.message}</SheetTitle>
              <SheetDescription className="font-mono break-all">
                {finding.file_path}:{finding.start_line}
                {finding.end_line !== finding.start_line ? `–${finding.end_line}` : ''}
              </SheetDescription>
              {finding.code_snippet && (
                <pre className="max-h-48 overflow-auto rounded-md border bg-muted/40 p-2 font-mono text-xs">
                  {finding.code_snippet}
                </pre>
              )}
            </div>
            <div className="flex-1 p-4">
              <FixPanel key={finding.id} scanId={scanId} finding={finding} />
            </div>
          </div>
        )}
      </SheetContent>
    </Sheet>
  )
}
