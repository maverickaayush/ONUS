'use client'

/**
 * Peripheral HUD chrome — ambient, non-interactive environment:
 *   AmbientTelemetry  top-right   PING_LATENCY / MEM_ALLOC / SECURE_CONN / ACTIVE_SESSION
 *   HexStream         bottom-left continuous hex, <10% opacity
 *   TypingOscilloscope bottom-right pulse graph reacting to keystrokes
 * All decorative; telemetry/hex update on slow intervals; the scope animates via
 * a ref-driven SVG polyline (no React state per frame).
 */
import { useEffect, useRef, useState } from 'react'

const CYAN = '#FFB000'

export function AmbientTelemetry() {
  const [t, setT] = useState({ ping: 12, mem: 47, conn: 'AES-256', sess: 'IDLE' })
  useEffect(() => {
    const id = window.setInterval(() => {
      setT({
        ping: 8 + Math.floor(Math.random() * 22),
        mem: 40 + Math.floor(Math.random() * 25),
        conn: 'AES-256',
        sess: Math.random() > 0.5 ? 'IDLE' : 'ARMED',
      })
    }, 2200)
    return () => window.clearInterval(id)
  }, [])
  const Row = ({ k, v }: { k: string; v: string }) => (
    <div className="flex justify-between gap-6">
      <span className="text-white/25">{k}</span>
      <span style={{ color: CYAN, opacity: 0.5 }}>{v}</span>
    </div>
  )
  return (
    <div className="pointer-events-none fixed right-5 top-5 z-20 hidden font-mono text-[9px] leading-relaxed sm:block">
      <Row k="PING_LATENCY" v={`${t.ping}ms`} />
      <Row k="MEM_ALLOC" v={`${t.mem}%`} />
      <Row k="SECURE_CONN" v={t.conn} />
      <Row k="ACTIVE_SESSION" v={t.sess} />
    </div>
  )
}

export function HexStream() {
  const [rows, setRows] = useState<string[]>([])
  useEffect(() => {
    const gen = () => '0x' + Math.floor(Math.random() * 256).toString(16).toUpperCase().padStart(2, '0')
    setRows(Array.from({ length: 14 }, gen))
    const id = window.setInterval(() => setRows((prev) => [gen(), ...prev.slice(0, 13)]), 260)
    return () => window.clearInterval(id)
  }, [])
  return (
    <div className="pointer-events-none fixed bottom-5 left-5 z-20 hidden font-mono text-[9px] leading-[1.4] text-white sm:block" style={{ opacity: 0.08 }}>
      {rows.map((r, i) => <div key={i}>{r}</div>)}
    </div>
  )
}

export function TypingOscilloscope() {
  const lineRef = useRef<SVGPolylineElement>(null)
  const amp = useRef(0)
  useEffect(() => {
    const N = 48, W = 120, H = 34
    const samples = new Array(N).fill(H / 2)
    let raf = 0
    const onKey = () => { amp.current = 1 }
    const loop = () => {
      amp.current *= 0.9
      samples.shift()
      // calm heartbeat when idle, sharp spike while typing
      const beat = Math.sin(performance.now() / 260) * 1.2
      const spike = amp.current > 0.05 ? (Math.random() - 0.5) * amp.current * (H * 0.9) : 0
      samples.push(H / 2 + beat + spike)
      const pts = samples.map((y, i) => `${(i / (N - 1)) * W},${y.toFixed(1)}`).join(' ')
      if (lineRef.current) lineRef.current.setAttribute('points', pts)
      raf = requestAnimationFrame(loop)
    }
    raf = requestAnimationFrame(loop)
    window.addEventListener('keydown', onKey)
    return () => { cancelAnimationFrame(raf); window.removeEventListener('keydown', onKey) }
  }, [])
  return (
    <div className="pointer-events-none fixed bottom-5 right-5 z-20 hidden sm:block" style={{ opacity: 0.5 }}>
      <svg width={120} height={34} aria-hidden="true">
        <polyline ref={lineRef} fill="none" stroke={CYAN} strokeWidth={1} points="" />
      </svg>
    </div>
  )
}
