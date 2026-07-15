'use client'

/**
 * TangleCanvas — a sparse computational-network backdrop drawn directly on a 2D
 * canvas (no Three.js / WebGL / particle library). Environmental atmosphere for
 * the auth experience; the card sits above it.
 *
 * Performance notes:
 *  - All simulation state lives in refs, never React state — zero rerenders/frame.
 *  - requestAnimationFrame with delta-time clamping so motion is refresh-rate
 *    independent and a dropped frame doesn't teleport nodes.
 *  - Proximity via a uniform spatial grid (cell = link distance), so connection
 *    lookup is ~O(n) not O(n²).
 *  - DPR capped at 2; backing store scaled once, logical coords stay in CSS px.
 *  - prefers-reduced-motion: renders the network but freezes motion + gravity.
 *  - StrictMode-safe: the effect cancels its rAF and removes every listener on
 *    cleanup, so a double-mount never leaves a second loop running.
 */
import { useEffect, useRef } from 'react'

interface Node {
  x: number
  y: number
  vx: number
  vy: number
  r: number
}

const LINK_DIST = 100 // px — connect nodes closer than this
const POINTER_DIST = 150 // px — pointer influence radius
const MAX_SPEED = 0.14 // px/ms cap
const BASE_SPEED = 0.012 // px/ms typical drift
const CYAN = '0, 240, 255' // #00F0FF as rgb triplet for rgba()

function nodeCountFor(w: number, h: number): number {
  // ~1 node per 13k px², clamped. Desktop (~1920×1080) → ~100; phones → ~30.
  const target = Math.round((w * h) / 13000)
  return Math.max(28, Math.min(100, target))
}

export function TangleCanvas() {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctxOrNull = canvas.getContext('2d')
    if (!ctxOrNull) return
    // Non-null aliases: TS resets control-flow narrowing inside the long-lived
    // animation closures below, so bind explicitly-typed handles here.
    const cnv: HTMLCanvasElement = canvas
    const ctx: CanvasRenderingContext2D = ctxOrNull

    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches

    let width = 0
    let height = 0
    let dpr = 1
    let nodes: Node[] = []
    const pointer = { x: 0, y: 0, active: false }
    let raf = 0
    let last = performance.now()

    const rand = (a: number, b: number) => a + Math.random() * (b - a)

    function makeNodes() {
      const count = nodeCountFor(width, height)
      nodes = Array.from({ length: count }, () => {
        const ang = Math.random() * Math.PI * 2
        const sp = reduced ? 0 : rand(BASE_SPEED * 0.4, BASE_SPEED)
        return {
          x: Math.random() * width,
          y: Math.random() * height,
          vx: Math.cos(ang) * sp,
          vy: Math.sin(ang) * sp,
          r: rand(0.5, 1.5),
        }
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
      // Reset any prior transform, then scale so we draw in logical CSS px.
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      makeNodes()
    }

    function drawBackground() {
      ctx.fillStyle = '#020208'
      ctx.fillRect(0, 0, width, height)
      // Ultra-subtle deep-indigo core, offset slightly up; fades to near-black.
      const g = ctx.createRadialGradient(
        width * 0.5,
        height * 0.42,
        0,
        width * 0.5,
        height * 0.42,
        Math.max(width, height) * 0.75,
      )
      g.addColorStop(0, 'rgba(38, 30, 92, 0.22)')
      g.addColorStop(0.45, 'rgba(12, 10, 40, 0.10)')
      g.addColorStop(1, 'rgba(2, 2, 8, 0)')
      ctx.fillStyle = g
      ctx.fillRect(0, 0, width, height)
    }

    // Uniform grid keyed by cell; only compare nodes in the same/adjacent cells.
    function buildGrid() {
      const cell = LINK_DIST
      const cols = Math.max(1, Math.ceil(width / cell))
      const grid = new Map<number, number[]>()
      const key = (cx: number, cy: number) => cy * cols + cx
      nodes.forEach((n, i) => {
        const cx = Math.min(cols - 1, Math.max(0, Math.floor(n.x / cell)))
        const cy = Math.max(0, Math.floor(n.y / cell))
        const k = key(cx, cy)
        const arr = grid.get(k)
        if (arr) arr.push(i)
        else grid.set(k, [i])
      })
      return { grid, cols, cell, key }
    }

    function drawConnections() {
      const { grid, cols, cell, key } = buildGrid()
      const maxSq = LINK_DIST * LINK_DIST
      ctx.lineWidth = 0.5
      grid.forEach((bucket, k) => {
        const cy = Math.floor(k / cols)
        const cx = k - cy * cols
        // neighbouring cells (including self); only forward to avoid dupes
        for (let dx = -1; dx <= 1; dx++) {
          for (let dy = -1; dy <= 1; dy++) {
            const nk = key(cx + dx, cy + dy)
            const other = grid.get(nk)
            if (!other) continue
            for (const i of bucket) {
              for (const j of other) {
                if (j <= i) continue
                const a = nodes[i]
                const b = nodes[j]
                const ddx = a.x - b.x
                const ddy = a.y - b.y
                const dSq = ddx * ddx + ddy * ddy
                if (dSq > maxSq) continue
                const t = 1 - Math.sqrt(dSq) / LINK_DIST
                const op = t * 0.2 // cap 20%
                if (op <= 0.01) continue
                ctx.strokeStyle = `rgba(${CYAN}, ${op.toFixed(3)})`
                ctx.beginPath()
                ctx.moveTo(a.x, a.y)
                ctx.lineTo(b.x, b.y)
                ctx.stroke()
              }
            }
          }
        }
      })
    }

    function drawPointer() {
      if (!pointer.active) return
      const maxSq = POINTER_DIST * POINTER_DIST
      ctx.lineWidth = 0.5
      for (const n of nodes) {
        const ddx = n.x - pointer.x
        const ddy = n.y - pointer.y
        const dSq = ddx * ddx + ddy * ddy
        if (dSq > maxSq) continue
        const dist = Math.sqrt(dSq) || 1
        const t = 1 - dist / POINTER_DIST
        ctx.strokeStyle = `rgba(${CYAN}, ${(t * 0.16).toFixed(3)})`
        ctx.beginPath()
        ctx.moveTo(n.x, n.y)
        ctx.lineTo(pointer.x, pointer.y)
        ctx.stroke()
        if (!reduced) {
          // Extremely gentle attraction; velocity is clamped below.
          const pull = (t * 0.00002) * dist
          n.vx -= (ddx / dist) * pull
          n.vy -= (ddy / dist) * pull
        }
      }
    }

    function drawNodes() {
      for (const n of nodes) {
        ctx.beginPath()
        ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2)
        ctx.fillStyle = `rgba(${CYAN}, 0.55)`
        ctx.fill()
      }
    }

    function step(dt: number) {
      if (reduced) return
      for (const n of nodes) {
        n.x += n.vx * dt
        n.y += n.vy * dt
        // mild damping so pointer pulls don't accumulate into a swarm
        n.vx *= 0.995
        n.vy *= 0.995
        const sp = Math.hypot(n.vx, n.vy)
        if (sp > MAX_SPEED) {
          n.vx = (n.vx / sp) * MAX_SPEED
          n.vy = (n.vy / sp) * MAX_SPEED
        }
        // keep a floor of drift so the field never fully stalls
        if (sp < BASE_SPEED * 0.25) {
          const a = Math.random() * Math.PI * 2
          n.vx += Math.cos(a) * BASE_SPEED * 0.3
          n.vy += Math.sin(a) * BASE_SPEED * 0.3
        }
        // wrap around edges (more elegant than bouncing for a suspended field)
        if (n.x < -5) n.x = width + 5
        else if (n.x > width + 5) n.x = -5
        if (n.y < -5) n.y = height + 5
        else if (n.y > height + 5) n.y = -5
      }
    }

    function frame(now: number) {
      const dt = Math.min(now - last, 50) // clamp long gaps (tab switch)
      last = now
      step(dt)
      drawBackground()
      drawConnections()
      drawPointer()
      drawNodes()
      raf = requestAnimationFrame(frame)
    }

    // ── listeners ──
    let resizeTimer = 0
    const onResize = () => {
      window.clearTimeout(resizeTimer)
      resizeTimer = window.setTimeout(resize, 150)
    }
    const onPointerMove = (e: PointerEvent) => {
      pointer.x = e.clientX
      pointer.y = e.clientY
      pointer.active = true
    }
    const onPointerLeave = () => {
      pointer.active = false
    }

    resize()
    window.addEventListener('resize', onResize)
    window.addEventListener('pointermove', onPointerMove, { passive: true })
    window.addEventListener('pointerleave', onPointerLeave)
    document.addEventListener('mouseleave', onPointerLeave)

    if (reduced) {
      // Static single paint — network visible, no loop.
      drawBackground()
      drawConnections()
      drawNodes()
    } else {
      last = performance.now()
      raf = requestAnimationFrame(frame)
    }

    return () => {
      cancelAnimationFrame(raf)
      window.clearTimeout(resizeTimer)
      window.removeEventListener('resize', onResize)
      window.removeEventListener('pointermove', onPointerMove)
      window.removeEventListener('pointerleave', onPointerLeave)
      document.removeEventListener('mouseleave', onPointerLeave)
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 -z-10"
      style={{ background: '#020208' }}
    />
  )
}
