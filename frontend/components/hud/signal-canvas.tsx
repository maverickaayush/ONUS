'use client'

/**
 * SignalCanvas — a raw-oscilloscope / signal-processor backdrop. True-black field,
 * a static graphite reference grid, and 5–7 horizontal phosphor-amber signal lines
 * that pan right. A magnetic cursor warps any line within 200px into a fluid sine/
 * spike disturbance whose amplitude scales with proximity and snaps flat when the
 * cursor leaves.
 *
 * Perf: points sampled every SAMPLE_STEP px and joined with lineTo (never per-pixel
 * distance math); all state in refs; delta-time rAF; DPR-scaled for sharp 1px lines;
 * prefers-reduced-motion freezes motion. Reads the shared `pointer` (written by the
 * TargetingReticle) so the interference follows the custom reticle.
 */
import { useEffect, useRef } from 'react'
import { pointer } from './emblem'

const BLACK = '#000000'
const GRID = '#151515'
const AMBER = '#FFB000'
const GRID_STEP = 40
const SAMPLE_STEP = 8
const RADIUS = 200
const AMP = 22
const LINE_COUNT = 6

interface Line { y: number; seed: number; speed: number }

export function SignalCanvas() {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctxOrNull = canvas.getContext('2d')
    if (!ctxOrNull) return
    const cnv: HTMLCanvasElement = canvas
    const ctx: CanvasRenderingContext2D = ctxOrNull

    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    let width = 0, height = 0, dpr = 1, t = 0, last = performance.now(), raf = 0
    let lines: Line[] = []

    function makeLines() {
      const n = 5 + Math.floor(Math.random() * 3) // 5..7
      lines = Array.from({ length: n }, () => ({
        y: Math.round(height * (0.12 + Math.random() * 0.76)),
        seed: Math.random() * 10000,
        speed: 26 + Math.random() * 34,
      }))
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
      if (lines.length === 0) makeLines()
      else lines.forEach((l) => { l.y = Math.min(l.y, height - 20) })
    }

    function grid() {
      ctx.fillStyle = BLACK
      ctx.fillRect(0, 0, width, height)
      ctx.strokeStyle = GRID
      ctx.lineWidth = 1
      ctx.beginPath()
      for (let x = 0.5; x <= width; x += GRID_STEP) { ctx.moveTo(x, 0); ctx.lineTo(x, height) }
      for (let y = 0.5; y <= height; y += GRID_STEP) { ctx.moveTo(0, y); ctx.lineTo(width, y) }
      ctx.stroke()
    }

    // vertical displacement of a line at x — magnetic interference near the cursor
    function offset(x: number, baseY: number): number {
      if (!pointer.active) return 0
      const dx = x - pointer.x, dy = baseY - pointer.y
      const d = Math.sqrt(dx * dx + dy * dy)
      if (d > RADIUS) return 0
      const f = 1 - d / RADIUS
      const ff = f * f // tighten the disturbance around the cursor
      // gentle magnetic pull toward the cursor + layered sine/spike ripple
      const pull = ff * (pointer.y - baseY) * 0.32
      const ripple = f * (Math.sin((x - pointer.x) * 0.05 + t * 1.2) * AMP
                        + Math.sin((x - pointer.x) * 0.17 - t * 1.8) * AMP * 0.45)
      return pull + ripple
    }

    function drawLine(l: Line) {
      ctx.beginPath()
      for (let x = 0; x <= width; x += SAMPLE_STEP) {
        const y = l.y + offset(x, l.y)
        if (x === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y)
      }
      ctx.strokeStyle = AMBER
      ctx.lineWidth = 1
      ctx.shadowColor = AMBER
      ctx.shadowBlur = 6
      ctx.stroke()
      ctx.shadowBlur = 0

      // a bright data packet travelling right along the line (the "pan")
      const px = ((t * l.speed * 6 + l.seed) % (width + 120)) - 60
      if (px >= 0 && px <= width) {
        const py = l.y + offset(px, l.y)
        ctx.beginPath()
        ctx.arc(px, py, 1.6, 0, Math.PI * 2)
        ctx.fillStyle = AMBER
        ctx.shadowColor = AMBER
        ctx.shadowBlur = 10
        ctx.fill()
        ctx.shadowBlur = 0
      }
    }

    function render() {
      grid()
      for (const l of lines) drawLine(l)
    }

    function frame(now: number) {
      const dt = Math.min(now - last, 50) / 1000
      last = now
      t += dt
      render()
      raf = requestAnimationFrame(frame)
    }

    let resizeTimer = 0
    const onResize = () => { window.clearTimeout(resizeTimer); resizeTimer = window.setTimeout(resize, 150) }
    resize()
    window.addEventListener('resize', onResize)
    if (reduced) render()
    else { last = performance.now(); raf = requestAnimationFrame(frame) }

    return () => { cancelAnimationFrame(raf); window.clearTimeout(resizeTimer); window.removeEventListener('resize', onResize) }
  }, [])

  return <canvas ref={canvasRef} aria-hidden="true" className="pointer-events-none fixed inset-0 -z-10" style={{ background: BLACK }} />
}
