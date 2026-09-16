import dagre from '@dagrejs/dagre'
import type { ArchitectureIssueType, GraphEdge, GraphNode } from '@/lib/api'

export const ISSUE_TYPE_LABELS: Record<ArchitectureIssueType, string> = {
  circular_dependency: 'Circular dependencies',
  layer_violation: 'Layering violations',
  god_module: 'God modules',
  orphan_module: 'Orphan modules',
}

type LayerStyle = { label: string; node: string; swatch: string }

/** Top layers are cool colors, bottom layers warm; both stacks share the scale. */
export const LAYER_STYLES: Record<string, LayerStyle> = {
  presentation: {
    label: 'Presentation (routes, controllers)',
    node: 'border-sky-300 bg-sky-50 dark:border-sky-800 dark:bg-sky-950',
    swatch: 'bg-sky-400',
  },
  ui: {
    label: 'UI (components, pages)',
    node: 'border-sky-300 bg-sky-50 dark:border-sky-800 dark:bg-sky-950',
    swatch: 'bg-sky-400',
  },
  service: {
    label: 'Service',
    node: 'border-violet-300 bg-violet-50 dark:border-violet-800 dark:bg-violet-950',
    swatch: 'bg-violet-400',
  },
  hooks: {
    label: 'Hooks',
    node: 'border-violet-300 bg-violet-50 dark:border-violet-800 dark:bg-violet-950',
    swatch: 'bg-violet-400',
  },
  api: {
    label: 'API client',
    node: 'border-teal-300 bg-teal-50 dark:border-teal-800 dark:bg-teal-950',
    swatch: 'bg-teal-400',
  },
  data: {
    label: 'Data (models, db)',
    node: 'border-amber-300 bg-amber-50 dark:border-amber-800 dark:bg-amber-950',
    swatch: 'bg-amber-400',
  },
  store: {
    label: 'Store (state)',
    node: 'border-amber-300 bg-amber-50 dark:border-amber-800 dark:bg-amber-950',
    swatch: 'bg-amber-400',
  },
}

export const UNLAYERED_STYLE: LayerStyle = {
  label: 'No inferred layer',
  node: 'border-border bg-card',
  swatch: 'bg-muted-foreground/40',
}

export const layerStyle = (layer: string | null) => (layer && LAYER_STYLES[layer]) || UNLAYERED_STYLE

export const NODE_HEIGHT = 52
const MIN_WIDTH = 140
const MAX_WIDTH = 280

/** Width grows with the square root of LOC, relative to the largest node in view. */
export function nodeWidth(loc: number, maxLoc: number): number {
  if (maxLoc <= 0) return MIN_WIDTH
  return Math.round(MIN_WIDTH + (MAX_WIDTH - MIN_WIDTH) * Math.sqrt(loc / maxLoc))
}

export type Positioned = { x: number; y: number; width: number }

/** Layered top-to-bottom layout: importers above the modules they import. */
export function layoutGraph(nodes: GraphNode[], edges: GraphEdge[]): Map<string, Positioned> {
  const graph = new dagre.graphlib.Graph()
  graph.setGraph({ rankdir: 'TB', nodesep: 24, ranksep: 70, marginx: 20, marginy: 20 })
  graph.setDefaultEdgeLabel(() => ({}))
  const maxLoc = Math.max(0, ...nodes.map((n) => n.loc))
  for (const node of nodes) {
    graph.setNode(node.id, { width: nodeWidth(node.loc, maxLoc), height: NODE_HEIGHT })
  }
  for (const edge of edges) {
    // Type-only edges don't constrain ranks, so cycles through types don't distort the layers.
    if (!edge.type_only) graph.setEdge(edge.source, edge.target)
  }
  dagre.layout(graph)
  const positions = new Map<string, Positioned>()
  for (const node of nodes) {
    const laid = graph.node(node.id)
    positions.set(node.id, { x: laid.x - laid.width / 2, y: laid.y - NODE_HEIGHT / 2, width: laid.width })
  }
  return positions
}

export function directoryOf(path: string): string {
  const index = path.lastIndexOf('/')
  return index === -1 ? '' : path.slice(0, index)
}

export function formatPercent(value: number): string {
  return `${(value * 100).toFixed(value >= 0.995 || value === 0 ? 0 : 1)}%`
}
