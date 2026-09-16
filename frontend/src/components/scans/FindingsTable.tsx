import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { SeverityBadge } from '@/components/scans/SeverityBadge'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import {
  type ApiError,
  type Finding,
  type FindingPage,
  getFindings,
  SEVERITIES,
  type Severity,
  type SeverityCounts,
} from '@/lib/api'

const PAGE_SIZE = 25

function formatLines(finding: Finding): string {
  return finding.start_line === finding.end_line
    ? `${finding.start_line}`
    : `${finding.start_line}–${finding.end_line}`
}

export function FindingsTable({ scanId, counts }: { scanId: string; counts: SeverityCounts }) {
  const [selected, setSelected] = useState<Severity[]>([])
  const [page, setPage] = useState(1)

  const findings = useQuery<FindingPage, ApiError>({
    queryKey: ['scan', scanId, 'findings', { severity: selected, page }],
    queryFn: () => getFindings(scanId, { severity: selected, page, pageSize: PAGE_SIZE }),
    placeholderData: keepPreviousData,
  })

  function toggleSeverity(severity: Severity) {
    setSelected((current) =>
      current.includes(severity) ? current.filter((s) => s !== severity) : [...current, severity],
    )
    setPage(1)
  }

  const data = findings.data
  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1

  return (
    <section className="space-y-3" aria-labelledby="findings-heading">
      <div className="flex flex-wrap items-center gap-2">
        <h2 id="findings-heading" className="mr-2 text-lg font-semibold">
          Findings
        </h2>
        {SEVERITIES.map((severity) => (
          <Button
            key={severity}
            size="sm"
            variant={selected.includes(severity) ? 'default' : 'outline'}
            aria-pressed={selected.includes(severity)}
            onClick={() => toggleSeverity(severity)}
            className="capitalize"
          >
            {severity}
            <span className="tabular-nums opacity-70">{counts[severity]}</span>
          </Button>
        ))}
        {selected.length > 0 && (
          <Button size="sm" variant="ghost" onClick={() => { setSelected([]); setPage(1) }}>
            Clear filter
          </Button>
        )}
      </div>

      {findings.isError ? (
        <p role="alert" className="text-sm text-destructive">
          Could not load findings: {findings.error.message}
        </p>
      ) : !data ? (
        <p className="text-sm text-muted-foreground">Loading findings…</p>
      ) : data.total === 0 ? (
        <div className="rounded-lg border border-dashed p-10 text-center text-sm text-muted-foreground">
          {selected.length > 0
            ? 'No findings match the selected severities.'
            : 'No findings. Semgrep did not report any issues in this codebase.'}
        </div>
      ) : (
        <>
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-24">Severity</TableHead>
                  <TableHead className="w-1/4">File</TableHead>
                  <TableHead className="w-20">Line</TableHead>
                  <TableHead>Message</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody className={findings.isPlaceholderData ? 'opacity-60' : undefined}>
                {data.items.map((finding) => (
                  <TableRow key={finding.id}>
                    <TableCell className="align-top">
                      <SeverityBadge severity={finding.severity} />
                    </TableCell>
                    <TableCell className="align-top font-mono text-xs break-all whitespace-normal">
                      {finding.file_path}
                    </TableCell>
                    <TableCell className="align-top font-mono text-xs">{formatLines(finding)}</TableCell>
                    <TableCell className="align-top whitespace-normal">
                      <p className="text-sm">{finding.message}</p>
                      <p className="mt-1 font-mono text-xs break-all text-muted-foreground">{finding.rule_id}</p>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <div className="flex items-center justify-between text-sm text-muted-foreground">
            <span>
              Showing {(data.page - 1) * data.page_size + 1}–{Math.min(data.page * data.page_size, data.total)} of{' '}
              {data.total}
            </span>
            <div className="flex gap-2">
              <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                Previous
              </Button>
              <Button size="sm" variant="outline" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
                Next
              </Button>
            </div>
          </div>
        </>
      )}
    </section>
  )
}
