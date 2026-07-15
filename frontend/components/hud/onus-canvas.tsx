'use client'

/**
 * OnusCanvas — the sparse computational-network backdrop (see TangleCanvas) with
 * two HUD upgrades:
 *   1. the gravity well follows the shared `pointer` (written by TargetingReticle),
 *      so the field responds to the custom reticle, not a separate cursor listener;
 *   2. one or two oversized ONUS emblem outlines (Path2D of the real emblem) that
 *      slowly emerge and dissolve in the field — the mark woven into the environment.
 *
 * All simulation state in refs; delta-time rAF; uniform spatial grid; DPR capped
 * at 2; prefers-reduced-motion freezes motion; StrictMode-safe cleanup.
 */
import { useEffect, useRef } from 'react'
import { ONUS_EMBLEM_PATH, ONUS_EMBLEM_VIEWBOX, pointer } from './emblem'

interface Node { x: number; y: number; vx: number; vy: number; r: number }

const LINK_DIST = 100
const POINTER_DIST = 150
const MAX_SPEED = 0.14
const BASE_SPEED = 0.012
const CYAN = '0, 240, 255'

function nodeCountFor(w: number, h: number) {
  return Math.max(28, Math.min(100, Math.round((w * h) / 13000)))
}

export function OnusCanvas() {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctxOrNull = canvas.getContext('2d')
    if (!ctxOrNull) return
    const cnv: HTMLCanvasElement = canvas
    const ctx: CanvasRenderingContext2D = ctxOrNull

    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    const emblem = new Path2D(ONUS_EMBLEM_PATH)
    let width = 0, height = 0, dpr = 1
    let nodes: Node[] = []
    let raf = 0
    let last = performance.now()
    let t = 0
    const rand = (a: number, b: number) => a + Math.random() * (b - a)

    function makeNodes() {
      const count = nodeCountFor(width, height)
      nodes = Array.from({ length: count }, () => {
        const ang = Math.random() * Math.PI * 2
        const sp = reduced ? 0 : rand(BASE_SPEED * 0.4, BASE_SPEED)
        return { x: Math.random() * width, y: Math.random() * height,
                 vx: Math.cos(ang) * sp, vy: Math.sin(ang) * sp, r: rand(0.5, 1.5) }
      })
    }

    function resize() {
      dpr = Math.min(window.devicePixelRatio || 1, 2)
      width = window.innerWidth
      height = window.innerHeight
      cnv.width = Math.round(width * dpr)
      cnv.height = Math.round(height * dpr)
      cnv.style.width = width + 'px'
      cnv.style.height = height + 'px'
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      makeNodes()
    }

    function background() {
      ctx.fillStyle = '#020208'
      ctx.fillRect(0, 0, width, height)
      const g = ctx.createRadialGradient(width * 0.5, height * 0.42, 0, width * 0.5, height * 0.42, Math.max(width, height) * 0.75)
      g.addColorStop(0, 'rgba(38, 30, 92, 0.20)')
      g.addColorStop(0.45, 'rgba(12, 10, 40, 0.09)')
      g.addColorStop(1, 'rgba(2, 2, 8, 0)')
      ctx.fillStyle = g
      ctx.fillRect(0, 0, width, height)
    }

    function drawEmblem() {
      // Two phase-shifted emblem outlines that emerge/dissolve; max ~3% opacity.
      const s = (Math.min(width, height) * 0.85) / ONUS_EMBLEM_VIEWBOX
      const half = (ONUS_EMBLEM_VIEWBOX / 2) * s
      for (const phase of [0, Math.PI]) {
        const op = (0.014 + 0.012 * (0.5 + 0.5 * Math.sin(t / 6000 + phase)))
        ctx.save()
        ctx.translate(width / 2, height / 2)
        ctx.scale(s, s)
        ctx.translate(-ONUS_EMBLEM_VIEWBOX / 2, -ONUS_EMBLEM_VIEWBOX / 2)
        ctx.lineWidth = (phase === 0 ? 2 : 1.2) / s
        ctx.strokeStyle = `rgba(${CYAN}, ${op.toFixed(3)})`
        ctx.stroke(emblem)
        ctx.restore()
      }
      void half
    }

    function grid() {
      const cell = LINK_DIST
      const cols = Math.max(1, Math.ceil(width / cell))
      const g = new Map<number, number[]>()
      const key = (cx: number, cy: number) => cy * cols + cx
      nodes.forEach((n, i) => {
        const cx = Math.min(cols - 1, Math.max(0, Math.floor(n.x / cell)))
        const cy = Math.max(0, Math.floor(n.y / cell))
        const k = key(cx, cy)
        const arr = g.get(k)
        if (arr) arr.push(i); else g.set(k, [i])
      })
      return { g, cols, key }
    }

    function connections() {
      const { g, cols, key } = grid()
      const maxSq = LINK_DIST * LINK_DIST
      ctx.lineWidth = 0.5
      g.forEach((bucket, k) => {
        const cy = Math.floor(k / cols)
        const cx = k - cy * cols
        for (let dx = -1; dx <= 1; dx++) for (let dy = -1; dy <= 1; dy++) {
          const other = g.get(key(cx + dx, cy + dy))
          if (!other) continue
          for (const i of bucket) for (const j of other) {
            if (j <= i) continue
            const a = nodes[i], b = nodes[j]
            const ddx = a.x - b.x, ddy = a.y - b.y
            const dSq = ddx * ddx + ddy * ddy
            if (dSq > maxSq) continue
            const op = (1 - Math.sqrt(dSq) / LINK_DIST) * 0.2
            if (op <= 0.01) continue
            ctx.strokeStyle = `rgba(${CYAN}, ${op.toFixed(3)})`
            ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke()
          }
        }
      })
    }

    function pointerInfluence() {
      if (!pointer.active) return
      const maxSq = POINTER_DIST * POINTER_DIST
      ctx.lineWidth = 0.5
      for (const n of nodes) {
        const ddx = n.x - pointer.x, ddy = n.y - pointer.y
        const dSq = ddx * ddx + ddy * ddy
        if (dSq > maxSq) continue
        const dist = Math.sqrt(dSq) || 1
        const tt = 1 - dist / POINTER_DIST
        ctx.strokeStyle = `rgba(${CYAN}, ${(tt * 0.16).toFixed(3)})`
        ctx.beginPath(); ctx.moveTo(n.x, n.y); ctx.lineTo(pointer.x, pointer.y); ctx.stroke()
        if (!reduced) { const pull = tt * 0.00002 * dist; n.vx -= (ddx / dist) * pull; n.vy -= (ddy / dist) * pull }
      }
    }

    function drawNodes() {
      ctx.fillStyle = `rgba(${CYAN}, 0.55)`
      for (const n of nodes) { ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2); ctx.fill() }
    }

    function step(dt: number) {
      if (reduced) return
      for (const n of nodes) {
        n.x += n.vx * dt; n.y += n.vy * dt
        n.vx *= 0.995; n.vy *= 0.995
        const sp = Math.hypot(n.vx, n.vy)
        if (sp > MAX_SPEED) { n.vx = (n.vx / sp) * MAX_SPEED; n.vy = (n.vy / sp) * MAX_SPEED }
        if (sp < BASE_SPEED * 0.25) { const a = Math.random() * Math.PI * 2; n.vx += Math.cos(a) * BASE_SPEED * 0.3; n.vy += Math.sin(a) * BASE_SPEED * 0.3 }
        if (n.x < -5) n.x = width + 5; else if (n.x > width + 5) n.x = -5
        if (n.y < -5) n.y = height + 5; else if (n.y > height + 5) n.y = -5
      }
    }

    function frame(now: number) {
      const dt = Math.min(now - last, 50); last = now; t += dt
      step(dt); background(); drawEmblem(); connections(); pointerInfluence(); drawNodes()
      raf = requestAnimationFrame(frame)
    }

    let resizeTimer = 0
    const onResize = () => { window.clearTimeout(resizeTimer); resizeTimer = window.setTimeout(resize, 150) }
    resize()
    window.addEventListener('resize', onResize)
    if (reduced) { background(); drawEmblem(); connections(); drawNodes() }
    else { last = performance.now(); raf = requestAnimationFrame(frame) }

    return () => { cancelAnimationFrame(raf); window.clearTimeout(resizeTimer); window.removeEventListener('resize', onResize) }
  }, [])

  return <canvas ref={canvasRef} aria-hidden="true" className="pointer-events-none fixed inset-0 -z-10" style={{ background: '#020208' }} />
}
