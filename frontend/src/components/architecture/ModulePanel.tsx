import { useQuery } from '@tanstack/react-query'
import { FolderClosed, FolderOpen, X } from 'lucide-react'
import { SeverityBadge } from '@/components/scans/SeverityBadge'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { directoryOf, layerStyle } from '@/lib/architecture'
import { type ApiError, getGraphModule, type GraphNode, type ModuleDetail, type ModuleImport } from '@/lib/api'

function Metric({ label, value }: { label: string; value: string | number }) {
  return (
    <div>
      <div className="text-[11px] text-muted-foreground">{label}</div>
      <div className="text-sm font-medium tabular-nums">{value}</div>
    </div>
  )
}

function ImportList({
  title,
  items,
  onSelect,
  empty,
}: {
  title: string
  items: ModuleImport[]
  onSelect?: (moduleId: string) => void
  empty: string
}) {
  return (
    <section className="space-y-1.5">
      <h4 className="text-xs font-semibold text-muted-foreground uppercase">
        {title} <span className="tabular-nums">({items.length})</span>
      </h4>
      {items.length === 0 ? (
        <p className="text-xs text-muted-foreground">{empty}</p>
      ) : (
        <ul className="space-y-1">
          {items.map((item) => (
            <li key={`${item.kind}:${item.module}:${item.line}`} className="text-xs">
              <div className="flex flex-wrap items-center gap-1">
                {onSelect && item.kind === 'internal' ? (
                  <button
                    type="button"
                    className="font-mono break-all text-left underline-offset-2 hover:underline"
                    onClick={() => onSelect(item.module)}
                  >
                    {item.path ?? item.module}
                  </button>
                ) : (
                  <span className="font-mono break-all">{item.module}</span>
                )}
                {item.type_only && <Badge variant="outline">type only</Badge>}
                {item.lazy && <Badge variant="outline">lazy</Badge>}
                {item.kind === 'external' && item.resolution === 'undeclared' && (
                  <Badge variant="outline" title="Imported but not listed in the project's dependency manifests">
                    undeclared
                  </Badge>
                )}
              </div>
              {item.kind === 'unresolved' && <div className="text-muted-foreground">{item.resolution}</div>}
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

function ModuleDetails({ detail, onSelectModule }: { detail: ModuleDetail; onSelectModule: (id: string) => void }) {
  const internal = detail.imports.filter((i) => i.kind === 'internal')
  const external = detail.imports.filter((i) => i.kind === 'external')
  const unresolved = detail.imports.filter((i) => i.kind === 'unresolved')
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-1.5">
        <Badge variant="secondary" className="gap-1.5">
          <span className={`size-2 rounded-full ${layerStyle(detail.layer).swatch}`} />
          {detail.layer ?? 'no layer'}
        </Badge>
        <Badge variant="secondary" className="capitalize">
          {detail.language}
        </Badge>
        {detail.is_entrypoint && <Badge variant="outline">entrypoint</Badge>}
        {detail.is_test && <Badge variant="outline">test</Badge>}
      </div>
      {detail.parse_error && (
        <p className="rounded-md border border-amber-300 bg-amber-50 p-2 text-xs text-amber-900 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-200">
          Skipped: {detail.parse_error}. Its imports are not in the graph.
        </p>
      )}
      <div className="grid grid-cols-3 gap-3">
        <Metric label="Lines of code" value={detail.loc.toLocaleString()} />
        <Metric label="Definitions" value={detail.definition_count} />
        <Metric label="Centrality" value={detail.centrality.toFixed(3)} />
        <Metric label="Fan-in" value={detail.fan_in} />
        <Metric label="Fan-out" value={detail.fan_out} />
        <Metric label="Instability" value={detail.instability === null ? '—' : detail.instability.toFixed(2)} />
      </div>
      {detail.issues.length > 0 && (
        <section className="space-y-1.5">
          <h4 className="text-xs font-semibold text-muted-foreground uppercase">Issues ({detail.issues.length})</h4>
          <ul className="space-y-2">
            {detail.issues.map((issue) => (
              <li key={issue.id} className="space-y-0.5 text-xs">
                <div className="flex items-center gap-1.5">
                  <SeverityBadge severity={issue.severity} />
                  <span className="font-medium">{issue.title}</span>
                </div>
                <p className="text-muted-foreground">{issue.description}</p>
              </li>
            ))}
          </ul>
        </section>
      )}
      <ImportList title="Imported by" items={detail.importers} onSelect={onSelectModule} empty="No internal importers." />
      <ImportList title="Imports" items={internal} onSelect={onSelectModule} empty="No internal imports." />
      <ImportList title="External packages" items={external} empty="None." />
      {unresolved.length > 0 && <ImportList title="Unresolved imports" items={unresolved} empty="" />}
      {detail.symbols.length > 0 && (
        <section className="space-y-1.5">
          <h4 className="text-xs font-semibold text-muted-foreground uppercase">
            Top-level symbols ({detail.symbols.length})
          </h4>
          <p className="font-mono text-xs break-words text-muted-foreground">{detail.symbols.join(', ')}</p>
        </section>
      )}
    </div>
  )
}

type Props = {
  scanId: string
  node: GraphNode | null
  moduleId: string
  onClose: () => void
  onSelectModule: (moduleId: string) => void
  onExpand: (directory: string) => void
  onCollapse: (directory: string) => void
}

export function ModulePanel({ scanId, node, moduleId, onClose, onSelectModule, onExpand, onCollapse }: Props) {
  const isDirectory = node?.kind === 'directory'
  const detail = useQuery<ModuleDetail, ApiError>({
    queryKey: ['scan', scanId, 'graph-module', moduleId],
    queryFn: () => getGraphModule(scanId, moduleId),
    enabled: !isDirectory,
  })
  const path = node?.path ?? detail.data?.path ?? moduleId
  const parent = directoryOf(path)

  return (
    <aside aria-label="Module details" className="flex h-full flex-col rounded-lg border bg-card">
      <div className="flex items-start justify-between gap-2 border-b p-3">
        <div className="min-w-0">
          <div className="text-xs text-muted-foreground">{isDirectory ? 'Directory' : 'Module'}</div>
          <h3 className="font-mono text-sm font-medium break-all">{path}</h3>
        </div>
        <Button size="icon-sm" variant="ghost" aria-label="Close details" onClick={onClose}>
          <X />
        </Button>
      </div>
      <div className="flex-1 space-y-4 overflow-y-auto p-3">
        {isDirectory && node ? (
          <div className="space-y-4">
            <div className="grid grid-cols-3 gap-3">
              <Metric label="Modules" value={node.module_count} />
              <Metric label="Lines of code" value={node.loc.toLocaleString()} />
              <Metric label="Unparsed files" value={node.parse_error_count} />
              <Metric label="Depends on" value={`${node.fan_out} nodes`} />
              <Metric label="Used by" value={`${node.fan_in} nodes`} />
              <Metric label="Max centrality" value={node.centrality.toFixed(3)} />
            </div>
            <Button size="sm" onClick={() => onExpand(node.path)}>
              <FolderOpen /> Expand directory
            </Button>
          </div>
        ) : detail.isError ? (
          <p className="text-sm text-destructive">{detail.error.message}</p>
        ) : !detail.data ? (
          <p className="text-sm text-muted-foreground">Loading module…</p>
        ) : (
          <ModuleDetails detail={detail.data} onSelectModule={onSelectModule} />
        )}
        {parent && (
          <Button size="sm" variant="outline" onClick={() => onCollapse(parent)}>
            <FolderClosed /> Collapse {parent.split('/').pop()}/
          </Button>
        )}
      </div>
    </aside>
  )
}
