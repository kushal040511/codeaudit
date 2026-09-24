import { useEffect, useRef } from 'react'

/**
 * The site's background: a measured grid with a slowly drifting module graph, like
 * the dependency graphs CodeAudit draws of your code.
 *
 * - Moving the pointer traces imports: nearby modules light up and their edges draw in.
 * - Clicking empty space sends a scan pulse along the edges; some modules it reaches
 *   get flagged in orange, then fade.
 * - Scrolling shifts the graph slightly (parallax).
 *
 * Rendered to one canvas behind everything; ignores clicks on interactive elements,
 * pauses in background tabs, and draws a single still frame for reduced motion.
 */

type GraphNode = {
  x: number
  y: number
  baseX: number
  baseY: number
  phase: number
  drift: number
  size: number
  layer: number
  glow: number
  flag: number
  flagged: boolean
}
type GraphEdge = { a: number; b: number; dash: number }
type Pulse = { reached: Map<number, number>; started: number; order: number[] }

const LAYERS = 5
const HOVER_RADIUS = 170
const HOP_MS = 130
const INTERACTIVE = 'a, button, input, textarea, select, label, summary, [role="button"], [role="tab"], [role="dialog"], pre, table, img, .monaco-editor, [data-no-pulse]'

function seeded(seed: number) {
  let value = seed
  return () => {
    value = (value * 16807) % 2147483647
    return (value - 1) / 2147483646
  }
}

function readPalette() {
  const style = getComputedStyle(document.documentElement)
  const get = (name: string, fallback: string) => style.getPropertyValue(name).trim() || fallback
  return {
    grid: get('--haze', '#c1d5df'),
    ink: get('--slate', '#46586b'),
    blueprint: get('--navy', '#37607e'),
    pencil: get('--flare', '#e35b0e'),
    graphite: get('--mist', '#8ca8ba'),
  }
}

function buildGraph(width: number, height: number) {
  const random = seeded(20260917)
  const count = Math.round(Math.min(90, Math.max(36, (width * height) / 26000)))
  const nodes: GraphNode[] = []
  for (let i = 0; i < count; i++) {
    const layer = Math.floor(random() * LAYERS)
    // Layers run top to bottom like an architecture diagram; x is free.
    const baseX = random() * width
    const baseY = ((layer + 0.2 + random() * 0.6) / LAYERS) * height
    nodes.push({
      x: baseX,
      y: baseY,
      baseX,
      baseY,
      phase: random() * Math.PI * 2,
      drift: 6 + random() * 14,
      size: 2 + random() * 2.5,
      layer,
      glow: 0,
      flag: 0,
      flagged: random() < 0.16,
    })
  }
  const edges: GraphEdge[] = []
  const seen = new Set<string>()
  nodes.forEach((node, index) => {
    // Imports mostly point down a layer, to nearby modules.
    const candidates = nodes
      .map((other, j) => ({ j, d: Math.hypot(other.baseX - node.baseX, other.baseY - node.baseY), other }))
      .filter(({ j, other }) => j !== index && other.layer >= node.layer && other.layer <= node.layer + 1)
      .sort((p, q) => p.d - q.d)
      .slice(0, 1 + Math.floor(random() * 3))
    for (const { j } of candidates) {
      const key = index < j ? `${index}-${j}` : `${j}-${index}`
      if (seen.has(key)) continue
      seen.add(key)
      edges.push({ a: index, b: j, dash: random() * 20 })
    }
  })
  return { nodes, edges }
}

export function BlueprintBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    const context = canvas?.getContext('2d')
    if (!canvas || !context) return
    const ctx: CanvasRenderingContext2D = context
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)')
    let palette = readPalette()
    let width = 0
    let height = 0
    let graph = buildGraph(1, 1)
    let neighbours: number[][] = []
    const pointer = { x: -9999, y: -9999, active: false }
    const pulses: Pulse[] = []
    let frame = 0
    let running = true
    const started = performance.now()

    function resize() {
      const ratio = Math.min(window.devicePixelRatio || 1, 2)
      width = window.innerWidth
      height = window.innerHeight
      canvas!.width = Math.round(width * ratio)
      canvas!.height = Math.round(height * ratio)
      ctx.setTransform(ratio, 0, 0, ratio, 0, 0)
      graph = buildGraph(width, height)
      neighbours = graph.nodes.map(() => [])
      for (const edge of graph.edges) {
        neighbours[edge.a].push(edge.b)
        neighbours[edge.b].push(edge.a)
      }
      palette = readPalette()
      if (reduced.matches) draw(started)
    }

    function drawGrid(offsetY: number) {
      const minor = 24
      ctx.lineWidth = 1
      ctx.strokeStyle = palette.grid
      ctx.globalAlpha = 0.45
      ctx.beginPath()
      for (let x = 0.5; x < width; x += minor) {
        ctx.moveTo(x, 0)
        ctx.lineTo(x, height)
      }
      const shift = ((offsetY % minor) + minor) % minor
      for (let y = 0.5 - shift; y < height; y += minor) {
        ctx.moveTo(0, y)
        ctx.lineTo(width, y)
      }
      ctx.stroke()
      ctx.globalAlpha = 0.9
      ctx.beginPath()
      for (let x = 0.5; x < width; x += minor * 5) {
        ctx.moveTo(x, 0)
        ctx.lineTo(x, height)
      }
      const majorShift = ((offsetY % (minor * 5)) + minor * 5) % (minor * 5)
      for (let y = 0.5 - majorShift; y < height; y += minor * 5) {
        ctx.moveTo(0, y)
        ctx.lineTo(width, y)
      }
      ctx.stroke()
      ctx.globalAlpha = 1
    }

    function draw(now: number) {
      const t = (now - started) / 1000
      const scroll = window.scrollY
      ctx.clearRect(0, 0, width, height)
      drawGrid(scroll * 0.25)

      // Page-load: the graph fades in over the first second.
      // On narrow screens the graph sits behind text, so it stays quieter.
      const quiet = width < 640 ? 0.55 : 1
      const intro = (reduced.matches ? 1 : Math.min(1, t / 1.2)) * quiet
      const parallax = scroll * 0.08

      for (const node of graph.nodes) {
        const wobble = reduced.matches ? 0 : 1
        node.x = node.baseX + Math.sin(t * 0.15 + node.phase) * node.drift * wobble
        node.y = node.baseY + Math.cos(t * 0.12 + node.phase) * node.drift * 0.6 * wobble - parallax
        const distance = Math.hypot(node.x - pointer.x, node.y - pointer.y)
        const target = pointer.active && distance < HOVER_RADIUS ? 1 - distance / HOVER_RADIUS : 0
        node.glow += (target - node.glow) * 0.12
        node.flag = Math.max(0, node.flag - 0.006)
      }

      for (const pulse of pulses) {
        const elapsed = now - pulse.started
        for (const index of pulse.order) {
          const at = pulse.reached.get(index)!
          if (elapsed >= at && elapsed < at + 60) {
            graph.nodes[index].glow = Math.max(graph.nodes[index].glow, 1)
            if (graph.nodes[index].flagged) graph.nodes[index].flag = 1
          }
        }
      }
      for (let i = pulses.length - 1; i >= 0; i--) {
        if (now - pulses[i].started > pulses[i].order.length * HOP_MS + 1500) pulses.splice(i, 1)
      }

      // Edges: faint ink; traced (dashed, animated) near the pointer or a pulse front.
      for (const edge of graph.edges) {
        const a = graph.nodes[edge.a]
        const b = graph.nodes[edge.b]
        const heat = Math.max(a.glow, b.glow)
        ctx.globalAlpha = (0.16 + heat * 0.6) * intro
        ctx.strokeStyle = heat > 0.05 ? palette.blueprint : palette.graphite
        ctx.lineWidth = 1 + heat * 0.8
        ctx.setLineDash(heat > 0.05 ? [6, 5] : [])
        ctx.lineDashOffset = reduced.matches ? 0 : -(t * 22 + edge.dash)
        ctx.beginPath()
        ctx.moveTo(a.x, a.y)
        ctx.lineTo(b.x, b.y)
        ctx.stroke()

        for (const pulse of pulses) {
          const elapsed = now - pulse.started
          const fromA = pulse.reached.get(edge.a)
          const fromB = pulse.reached.get(edge.b)
          if (fromA === undefined || fromB === undefined || Math.abs(fromA - fromB) !== HOP_MS) continue
          const [from, to, at] = fromA < fromB ? [a, b, fromA] : [b, a, fromB]
          const progress = (elapsed - at) / HOP_MS
          if (progress <= 0 || progress >= 1.6) continue
          const p = Math.min(1, progress)
          ctx.setLineDash([])
          ctx.globalAlpha = (1 - Math.max(0, progress - 1) / 0.6) * intro
          ctx.strokeStyle = palette.blueprint
          ctx.lineWidth = 2
          ctx.beginPath()
          ctx.moveTo(from.x, from.y)
          ctx.lineTo(from.x + (to.x - from.x) * p, from.y + (to.y - from.y) * p)
          ctx.stroke()
        }
      }
      ctx.setLineDash([])

      for (const node of graph.nodes) {
        ctx.globalAlpha = (0.55 + node.glow * 0.45) * intro
        ctx.fillStyle = node.glow > 0.05 ? palette.blueprint : palette.ink
        const size = node.size + node.glow * 2.5
        ctx.fillRect(node.x - size / 2, node.y - size / 2, size, size)
        if (node.flag > 0) {
          // A square bracket closing on the flagged module, like a measurement being taken.
          ctx.globalAlpha = node.flag * intro
          ctx.strokeStyle = palette.pencil
          ctx.lineWidth = 1.6
          const reach = 9 + (1 - node.flag) * 7
          ctx.beginPath()
          ctx.strokeRect(node.x - reach, node.y - reach, reach * 2, reach * 2)
          ctx.stroke()
        }
      }
      ctx.globalAlpha = 1
    }

    function loop(now: number) {
      if (!running) return
      draw(now)
      frame = requestAnimationFrame(loop)
    }

    function startPulse(x: number, y: number) {
      let nearest = 0
      let best = Infinity
      graph.nodes.forEach((node, index) => {
        const d = Math.hypot(node.x - x, node.y - y)
        if (d < best) {
          best = d
          nearest = index
        }
      })
      const reached = new Map<number, number>([[nearest, 0]])
      const order = [nearest]
      for (let i = 0; i < order.length && order.length < 40; i++) {
        for (const next of neighbours[order[i]]) {
          if (!reached.has(next)) {
            reached.set(next, reached.get(order[i])! + HOP_MS)
            order.push(next)
          }
        }
      }
      pulses.push({ reached, started: performance.now(), order })
    }

    function onMove(event: PointerEvent) {
      pointer.x = event.clientX
      pointer.y = event.clientY
      pointer.active = event.pointerType === 'mouse' || event.pointerType === 'pen'
    }
    function onLeave() {
      pointer.active = false
    }
    function onDown(event: PointerEvent) {
      if (reduced.matches || event.button !== 0) return
      const target = event.target as Element | null
      if (target?.closest(INTERACTIVE)) return
      startPulse(event.clientX, event.clientY)
    }
    function onVisibility() {
      if (reduced.matches) return
      if (document.hidden) {
        running = false
        cancelAnimationFrame(frame)
      } else if (!running) {
        running = true
        frame = requestAnimationFrame(loop)
      }
    }
    function onMotionChange() {
      cancelAnimationFrame(frame)
      running = !reduced.matches
      if (running) frame = requestAnimationFrame(loop)
      else draw(performance.now())
    }

    resize()
    window.addEventListener('resize', resize)
    window.addEventListener('pointermove', onMove, { passive: true })
    window.addEventListener('pointerdown', onDown)
    document.documentElement.addEventListener('pointerleave', onLeave)
    document.addEventListener('visibilitychange', onVisibility)
    reduced.addEventListener('change', onMotionChange)
    if (reduced.matches) {
      running = false
      window.addEventListener('scroll', onScrollStill, { passive: true })
    } else {
      frame = requestAnimationFrame(loop)
      // The one orchestrated moment: a first scan pulse sweeps the graph after load.
      window.setTimeout(() => startPulse(width * 0.72, height * 0.3), 900)
    }
    function onScrollStill() {
      draw(performance.now())
    }

    return () => {
      running = false
      cancelAnimationFrame(frame)
      window.removeEventListener('resize', resize)
      window.removeEventListener('pointermove', onMove)
      window.removeEventListener('pointerdown', onDown)
      window.removeEventListener('scroll', onScrollStill)
      document.documentElement.removeEventListener('pointerleave', onLeave)
      document.removeEventListener('visibilitychange', onVisibility)
      reduced.removeEventListener('change', onMotionChange)
    }
  }, [])

  return <canvas ref={canvasRef} aria-hidden className="pointer-events-none fixed inset-0 z-0 h-full w-full" />
}
