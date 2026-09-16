import { Handle, type Node, type NodeProps, Position } from '@xyflow/react'
import { FolderClosed, TriangleAlert } from 'lucide-react'
import { memo } from 'react'
import { layerStyle, NODE_HEIGHT } from '@/lib/architecture'
import type { GraphNode } from '@/lib/api'
import { cn } from '@/lib/utils'

export type ModuleNodeData = {
  node: GraphNode
  width: number
  dimmed: boolean
  highlighted: boolean
  selected: boolean
}

export type ModuleFlowNode = Node<ModuleNodeData, 'module'>

function ModuleNodeComponent({ data }: NodeProps<ModuleFlowNode>) {
  const { node, width, dimmed, highlighted, selected } = data
  const directory = node.kind === 'directory'
  return (
    <div
      style={{ width, height: NODE_HEIGHT }}
      className={cn(
        'flex flex-col justify-center rounded-md border px-2.5 text-left shadow-xs transition-opacity',
        layerStyle(node.layer).node,
        directory && 'border-dashed',
        dimmed && 'opacity-20',
        highlighted && 'ring-2 ring-red-500',
        selected && 'ring-2 ring-primary',
      )}
      title={node.path}
    >
      <Handle type="target" position={Position.Top} className="!size-1.5 !min-h-0 !min-w-0 !border-0 !bg-muted-foreground/50" />
      <div className="flex min-w-0 items-center gap-1.5 text-xs font-medium">
        {directory && <FolderClosed aria-hidden className="size-3.5 shrink-0 text-muted-foreground" />}
        <span className="truncate">{node.label}</span>
        {node.issue_ids.length > 0 && (
          <TriangleAlert aria-label={`${node.issue_ids.length} issues`} className="ml-auto size-3.5 shrink-0 text-red-600" />
        )}
      </div>
      <div className="truncate text-[10px] text-muted-foreground tabular-nums">
        {directory ? `${node.module_count} modules · ` : ''}
        {node.loc.toLocaleString()} LOC · in {node.fan_in} · out {node.fan_out}
      </div>
      <Handle type="source" position={Position.Bottom} className="!size-1.5 !min-h-0 !min-w-0 !border-0 !bg-muted-foreground/50" />
    </div>
  )
}

export const ModuleNode = memo(ModuleNodeComponent)
