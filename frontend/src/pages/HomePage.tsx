import { useQuery } from '@tanstack/react-query'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { getHealth } from '@/lib/api'

export function HomePage() {
  const health = useQuery({ queryKey: ['health'], queryFn: getHealth, refetchInterval: 15_000 })

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
      <Card className="max-w-md">
        <CardHeader>
          <CardTitle>Backend status</CardTitle>
          <CardDescription>
            {health.data ? `API v${health.data.version}` : 'Checking /health…'}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          {health.isError && <Badge variant="destructive">API unreachable</Badge>}
          {health.data &&
            Object.entries(health.data.checks).map(([name, check]) => (
              <div key={name} className="flex items-center justify-between text-sm">
                <span className="capitalize">{name}</span>
                <Badge variant={check.status === 'ok' ? 'secondary' : 'destructive'}>
                  {check.status === 'ok' ? `ok · ${check.latency_ms} ms` : (check.detail ?? 'error')}
                </Badge>
              </div>
            ))}
        </CardContent>
      </Card>
    </div>
  )
}
