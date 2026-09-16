import {
  Background,
  Controls,
  type Edge,
  MarkerType,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { useEffect, useMemo } from 'react'
import { type ModuleFlowNode, ModuleNode } from '@/components/architecture/ModuleNode'
import { layoutGraph } from '@/lib/architecture'
import type { ArchitectureGraph, GraphIssueRef } from '@/lib/api'

const nodeTypes = { module: ModuleNode }
const PROBLEM_COLOR = '#dc2626'
const EDGE_COLOR = '#94a3b8'

type Props = {
  graph: ArchitectureGraph
  highlightedIssue: GraphIssueRef | null
  selectedNodeId: string | null
  onNodeClick: (nodeId: string) => void
}

function GraphCanvas({ graph, highlightedIssue, selectedNodeId, onNodeClick }: Props) {
  const { fitView } = useReactFlow()
  const positions = useMemo(() => layoutGraph(graph.nodes, graph.edges), [graph.nodes, graph.edges])

  const highlightNodes = useMemo(() => new Set(highlightedIssue?.node_ids ?? []), [highlightedIssue])
  const highlightEdges = useMemo(() => new Set(highlightedIssue?.edge_ids ?? []), [highlightedIssue])
  const highlighting = highlightedIssue !== null

  const nodes: ModuleFlowNode[] = useMemo(
    () =>
      graph.nodes.map((node) => {
        const position = positions.get(node.id) ?? { x: 0, y: 0, width: 160 }
        return {
          id: node.id,
          type: 'module',
          position: { x: position.x, y: position.y },
          data: {
            node,
            width: position.width,
            dimmed: highlighting && !highlightNodes.has(node.id),
            highlighted: highlighting && highlightNodes.has(node.id),
            selected: node.id === selectedNodeId,
          },
          draggable: false,
          connectable: false,
        }
      }),
    [graph.nodes, positions, highlighting, highlightNodes, selectedNodeId],
  )

  const edges: Edge[] = useMemo(
    () =>
      graph.edges.map((edge) => {
        const problem = edge.in_cycle || edge.layer_violation
        const active = !highlighting || highlightEdges.has(edge.id)
        const color = problem ? PROBLEM_COLOR : EDGE_COLOR
        return {
          id: edge.id,
          source: edge.source,
          target: edge.target,
          markerEnd: { type: MarkerType.ArrowClosed, color, width: 14, height: 14 },
          style: {
            stroke: color,
            strokeWidth: problem || highlightEdges.has(edge.id) ? 2 : 1,
            strokeDasharray: edge.type_only ? '4 3' : undefined,
            opacity: active ? 1 : 0.08,
          },
          zIndex: problem ? 1 : 0,
          focusable: false,
        }
      }),
    [graph.edges, highlighting, highlightEdges],
  )

  // Re-fit when the view changes shape (expand/collapse, new scan).
  useEffect(() => {
    const frame = requestAnimationFrame(() => fitView({ padding: 0.1, duration: 200 }))
    return () => cancelAnimationFrame(frame)
  }, [positions, fitView])

  // Bring a highlighted issue into view.
  useEffect(() => {
    if (!highlightedIssue?.node_ids.length) return
    fitView({ nodes: highlightedIssue.node_ids.map((id) => ({ id })), padding: 0.4, duration: 300, maxZoom: 1.2 })
  }, [highlightedIssue, fitView])

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      onNodeClick={(_, node) => onNodeClick(node.id)}
      nodesDraggable={false}
      nodesConnectable={false}
      elementsSelectable={false}
      minZoom={0.05}
      fitView
      proOptions={{ hideAttribution: true }}
    >
      <Background gap={24} />
      <Controls showInteractive={false} />
      <MiniMap pannable zoomable nodeStrokeWidth={2} className="!hidden md:!block" />
    </ReactFlow>
  )
}

export function ArchitectureGraphView(props: Props) {
  return (
    <ReactFlowProvider>
      <GraphCanvas {...props} />
    </ReactFlowProvider>
  )
}
