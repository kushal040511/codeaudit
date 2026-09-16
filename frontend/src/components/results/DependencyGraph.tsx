import { Background, Controls, ReactFlow, type Edge, type Node } from '@xyflow/react'
import '@xyflow/react/dist/style.css'

export function DependencyGraph({ nodes, edges }: { nodes: Node[]; edges: Edge[] }) {
  // TODO: auto-layout (e.g. dagre/elkjs), highlight cycles and high fan-in modules.
  return (
    <div className="h-80 rounded-lg border">
      <ReactFlow nodes={nodes} edges={edges} fitView proOptions={{ hideAttribution: false }}>
        <Background />
        <Controls />
      </ReactFlow>
    </div>
  )
}
