import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { RotateCcw, TriangleAlert } from 'lucide-react'
import { useMemo, useState } from 'react'
import { ArchitectureGraphView, type GraphHighlight } from '@/components/architecture/ArchitectureGraphView'
import { ArchitectureReviewPanel } from '@/components/architecture/ArchitectureReviewPanel'
import { IssuesList } from '@/components/architecture/IssuesList'
import { ModulePanel } from '@/components/architecture/ModulePanel'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { formatPercent, type Highlight, LAYER_STYLES, UNLAYERED_STYLE } from '@/lib/architecture'
import {
  type ApiError,
  type ArchitectureGraph,
  type ArchitectureIssue,
  getArchitectureGraph,
  getArchitectureIssues,
} from '@/lib/api'

const MAX_NODE_OPTIONS = [100, 300, 1000]
const LOW_COVERAGE = 0.85

function Stat({ label, value, alert }: { label: string; value: string | number; alert?: boolean }) {
  return (
    <div>
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className={`text-lg font-semibold tabular-nums ${alert ? 'text-red-600 dark:text-red-400' : ''}`}>{value}</div>
    </div>
  )
}

function Legend({ layers }: { layers: Record<string, number> }) {
  const present = Object.keys(layers).filter((layer) => layer in LAYER_STYLES)
  const swatches = [...new Map(present.map((layer) => [LAYER_STYLES[layer].label, LAYER_STYLES[layer]])).values()]
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
      {[...swatches, UNLAYERED_STYLE].map((style) => (
        <span key={style.label} className="inline-flex items-center gap-1.5">
          <span className={`size-2.5 rounded-sm ${style.swatch}`} />
          {style.label}
        </span>
      ))}
      <span className="inline-flex items-center gap-1.5">
        <span className="h-0.5 w-4 bg-red-600" /> Cycle or layering violation
      </span>
      <span className="inline-flex items-center gap-1.5">
        <span className="w-4 border-t border-dashed border-slate-400" /> Type-only import
      </span>
    </div>
  )
}

export function ArchitectureTab({ scanId, enrichmentNote }: { scanId: string; enrichmentNote: string }) {
  const [maxNodes, setMaxNodes] = useState(300)
  const [expand, setExpand] = useState<string[]>([])
  const [collapse, setCollapse] = useState<string[]>([])
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)
  const [selectedIssueId, setSelectedIssueId] = useState<number | null>(null)
  const [citation, setCitation] = useState<Highlight | null>(null)

  const graphQuery = useQuery<ArchitectureGraph, ApiError>({
    queryKey: ['scan', scanId, 'graph', { maxNodes, expand, collapse }],
    queryFn: () => getArchitectureGraph(scanId, { maxNodes, expand, collapse }),
    placeholderData: keepPreviousData,
  })
  const issuesQuery = useQuery<ArchitectureIssue[], ApiError>({
    queryKey: ['scan', scanId, 'architecture-issues'],
    queryFn: () => getArchitectureIssues(scanId),
  })

  const graph = graphQuery.data
  const highlight: GraphHighlight | null = useMemo(
    () => citation ?? graph?.issues.find((issue) => issue.id === selectedIssueId) ?? null,
    [graph, selectedIssueId, citation],
  )

  function selectIssue(issueId: number | null) {
    setCitation(null)
    setSelectedIssueId(issueId)
  }

  function selectCitation(next: Highlight | null) {
    setSelectedIssueId(null)
    setCitation(next)
  }
  const selectedNode = graph?.nodes.find((node) => node.id === selectedNodeId) ?? null

  function expandDirectory(directory: string) {
    setCollapse((current) => current.filter((c) => c !== directory && !c.startsWith(`${directory}/`)))
    setExpand((current) => [...new Set([...current, directory])])
    setSelectedNodeId(null)
  }

  function collapseDirectory(directory: string) {
    setExpand((current) => current.filter((e) => e !== directory && !e.startsWith(`${directory}/`)))
    setCollapse((current) => [...new Set([...current.filter((c) => !c.startsWith(`${directory}/`)), directory])])
    setSelectedNodeId(`dir:${directory}`)
  }

  function resetView() {
    setExpand([])
    setCollapse([])
    setSelectedNodeId(null)
  }

  if (graphQuery.isError && !graph) {
    return <p className="text-sm text-destructive">Could not load the architecture graph: {graphQuery.error.message}</p>
  }
  if (!graph) return <p className="text-sm text-muted-foreground">Loading architecture graph…</p>

  const { summary, view } = graph
  const resolution = summary.resolution
  const lowCoverage = resolution.total > 0 && resolution.coverage < LOW_COVERAGE

  return (
    <div className="space-y-4">
      <Card>
        <CardContent className="grid grid-cols-2 gap-4 sm:grid-cols-4 lg:grid-cols-8">
          <Stat label="Modules" value={summary.node_count.toLocaleString()} />
          <Stat label="Dependencies" value={summary.edge_count.toLocaleString()} />
          <Stat label="Imports resolved" value={formatPercent(resolution.coverage)} alert={lowCoverage} />
          <Stat label="Max depth" value={summary.max_depth} />
          <Stat
            label="Import cycles"
            value={`${summary.cycle_count}${summary.cycles_truncated ? '+' : ''}`}
            alert={summary.cycle_count > 0}
          />
          <Stat label="Layer violations" value={summary.layer_violation_count} alert={summary.layer_violation_count > 0} />
          <Stat label="God modules" value={summary.god_module_count} />
          <Stat label="Orphans" value={summary.orphan_count} />
        </CardContent>
      </Card>

      {(lowCoverage || summary.parse.skipped > 0) && (
        <div
          role="note"
          className="space-y-1 rounded-lg border border-amber-300 bg-amber-50/60 p-3 text-sm dark:border-amber-900 dark:bg-amber-950/30"
        >
          {lowCoverage && (
            <p className="flex gap-1.5">
              <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-amber-600" />
              Only {formatPercent(resolution.coverage)} of {resolution.total.toLocaleString()} imports could be resolved;
              the graph is missing dependencies. Most common failures:{' '}
              {Object.entries(resolution.unresolved_by_form)
                .slice(0, 3)
                .map(([form, count]) => `${form} (${count})`)
                .join(', ')}
              .
            </p>
          )}
          {summary.parse.skipped > 0 && (
            <p className="flex gap-1.5">
              <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-amber-600" />
              {summary.parse.skipped} file(s) could not be parsed, so their imports are missing:{' '}
              {summary.parse.skipped_files
                .slice(0, 3)
                .map((f) => f.path)
                .join(', ')}
              {summary.parse.skipped > 3 ? '…' : ''}
            </p>
          )}
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between gap-2">
        <Legend layers={summary.layers} />
        <div className="flex flex-wrap items-center gap-2 text-sm">
          {view.aggregated && (
            <Badge variant="secondary">
              {graph.nodes.length} nodes for {view.total_modules.toLocaleString()} modules
              {view.depth !== null ? ` · grouped at directory depth ${view.depth}` : ''}
            </Badge>
          )}
          <label className="inline-flex items-center gap-1.5 text-muted-foreground">
            Max nodes
            <select
              value={maxNodes}
              onChange={(event) => setMaxNodes(Number(event.target.value))}
              className="rounded-md border bg-background px-1.5 py-1 text-foreground"
            >
              {MAX_NODE_OPTIONS.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </label>
          {(expand.length > 0 || collapse.length > 0) && (
            <Button size="sm" variant="outline" onClick={resetView}>
              <RotateCcw /> Reset view
            </Button>
          )}
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-[18rem_minmax(0,1fr)]">
        <div className="max-h-[40rem] overflow-y-auto pr-1 lg:order-none">
          {issuesQuery.isError ? (
            <p className="text-sm text-destructive">Could not load issues: {issuesQuery.error.message}</p>
          ) : !issuesQuery.data ? (
            <p className="text-sm text-muted-foreground">Loading issues…</p>
          ) : (
            <Tabs defaultValue="detected" className="gap-3">
              <TabsList>
                <TabsTrigger value="detected">Detected</TabsTrigger>
                <TabsTrigger value="review">AI review</TabsTrigger>
              </TabsList>
              <TabsContent value="detected">
                <IssuesList issues={issuesQuery.data} selectedId={selectedIssueId} onSelect={selectIssue} />
              </TabsContent>
              <TabsContent value="review">
                <ArchitectureReviewPanel
                  scanId={scanId}
                  graph={graph}
                  enrichmentNote={enrichmentNote}
                  highlightKey={citation?.key ?? null}
                  onHighlight={selectCitation}
                />
              </TabsContent>
            </Tabs>
          )}
        </div>

        <div className={`grid gap-4 ${selectedNodeId ? 'xl:grid-cols-[minmax(0,1fr)_22rem]' : ''}`}>
          <div className={`h-[40rem] rounded-lg border bg-background ${graphQuery.isPlaceholderData ? 'opacity-60' : ''}`}>
            {graph.nodes.length === 0 ? (
              <p className="p-6 text-sm text-muted-foreground">No Python, JavaScript or TypeScript modules found.</p>
            ) : (
              <ArchitectureGraphView
                graph={graph}
                highlight={highlight}
                selectedNodeId={selectedNodeId}
                onNodeClick={setSelectedNodeId}
              />
            )}
          </div>
          {selectedNodeId && (
            <div className="h-[40rem]">
              <ModulePanel
                key={selectedNodeId}
                scanId={scanId}
                node={selectedNode}
                moduleId={selectedNodeId}
                onClose={() => setSelectedNodeId(null)}
                onSelectModule={setSelectedNodeId}
                onExpand={expandDirectory}
                onCollapse={collapseDirectory}
              />
            </div>
          )}
        </div>
      </div>

      {graph.external_dependencies.length > 0 && (
        <section aria-labelledby="external-deps" className="space-y-2">
          <h3 id="external-deps" className="text-sm font-semibold">
            External dependencies <span className="font-normal text-muted-foreground">(by importing modules)</span>
          </h3>
          <div className="flex flex-wrap gap-1.5">
            {graph.external_dependencies.slice(0, 40).map((dep) => (
              <Badge
                key={`${dep.language}:${dep.name}`}
                variant={dep.evidence === 'undeclared' ? 'outline' : 'secondary'}
                title={`${dep.language} · ${dep.evidence ?? ''} · ${dep.import_count} imports`}
              >
                {dep.name}
                <span className="tabular-nums opacity-70">{dep.importer_count}</span>
              </Badge>
            ))}
          </div>
        </section>
      )}
    </div>
  )
}
