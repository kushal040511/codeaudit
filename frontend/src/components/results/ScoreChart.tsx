import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

export type CategoryScore = { category: string; score: number; maxScore: number }

export function ScoreChart({ categories }: { categories: CategoryScore[] }) {
  if (categories.length === 0) {
    return <EmptyPanel label="No score data yet" />
  }
  // TODO: overall score gauge + per-category breakdown.
  return (
    <div className="h-80 rounded-lg border p-4">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={categories}>
          <CartesianGrid strokeDasharray="3 3" vertical={false} />
          <XAxis dataKey="category" />
          <YAxis domain={[0, 100]} />
          <Tooltip />
          <Bar dataKey="score" fill="var(--chart-1)" radius={4} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

function EmptyPanel({ label }: { label: string }) {
  return (
    <div className="flex h-80 items-center justify-center rounded-lg border text-sm text-muted-foreground">
      {label}
    </div>
  )
}
