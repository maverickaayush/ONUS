'use client'

/**
 * TargetingReticle — a precision-instrument cursor. Coordinates live in refs and
 * are applied via a single rAF-driven transform (never React state per frame).
 * Hover mode (idle / clickable / text) is the only React state, and it changes
 * only on pointer enter/leave of interactive elements — not every frame.
 *
 * Modes:
 *   idle       2×2 white dot + four faint 1px brackets held off-center
 *   clickable  brackets snap inward, recolor to cyan (#FFB000)
 *   text       morphs into a thin pulsing cyan I-beam
 *
 * Writes the live position into the shared `pointer` so the canvas gravity well
 * follows the reticle. Hidden on touch / coarse pointers (no cursor to replace).
 */
import { useEffect, useRef, useState } from 'react'
import { pointer } from './emblem'

type Mode = 'idle' | 'clickable' | 'text'

const CLICKABLE = 'a,button,[role="button"],label,summary,[data-reticle="click"]'
const TEXTUAL = 'input,textarea,[contenteditable="true"]'

export function TargetingReticle() {
  const dotRef = useRef<HTMLDivElement>(null)
  const [mode, setMode] = useState<Mode>('idle')
  const [visible, setVisible] = useState(false)

  useEffect(() => {
    if (window.matchMedia('(pointer: coarse)').matches) return
    const pos = { x: window.innerWidth / 2, y: window.innerHeight / 2 }
    let raf = 0

    const onMove = (e: MouseEvent) => {
      pos.x = e.clientX
      pos.y = e.clientY
      pointer.x = e.clientX
      pointer.y = e.clientY
      pointer.active = true
      if (!visible) setVisible(true)
    }
    const onOver = (e: MouseEvent) => {
      const t = e.target as Element | null
      if (t?.closest?.(TEXTUAL)) setMode('text')
      else if (t?.closest?.(CLICKABLE)) setMode('clickable')
      else setMode('idle')
    }
    const onLeave = () => {
      setVisible(false)
      pointer.active = false
    }

    const loop = () => {
      const el = dotRef.current
      if (el) el.style.transform = `translate3d(${pos.x}px, ${pos.y}px, 0) translate(-50%, -50%)`
      raf = requestAnimationFrame(loop)
    }
    raf = requestAnimationFrame(loop)
    window.addEventListener('mousemove', onMove, { passive: true })
    window.addEventListener('mouseover', onOver, { passive: true })
    document.addEventListener('mouseleave', onLeave)

    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('mouseover', onOver)
      document.removeEventListener('mouseleave', onLeave)
    }
  }, [visible])

  const cyan = '#FFB000'
  // bracket offset: further out when idle, snapped in when targeting
  const off = mode === 'idle' ? 9 : 5
  const brColor = mode === 'idle' ? 'rgba(255,255,255,0.5)' : cyan
  const brackets = [
    { c: 'top-0 left-0', b: 'borderTop borderLeft', tx: -off, ty: -off },
    { c: 'top-0 right-0', b: 'borderTop borderRight', tx: off, ty: -off },
    { c: 'bottom-0 left-0', b: 'borderBottom borderLeft', tx: -off, ty: off },
    { c: 'bottom-0 right-0', b: 'borderBottom borderRight', tx: off, ty: off },
  ]

  return (
    <div
      ref={dotRef}
      aria-hidden="true"
      className="pointer-events-none fixed left-0 top-0 z-[9999]"
      style={{ opacity: visible ? 1 : 0, transition: 'opacity 200ms', willChange: 'transform', mixBlendMode: 'screen' }}
    >
      {mode === 'text' ? (
        <div className="onus-ibeam" style={{ background: cyan }} />
      ) : (
        <div className="relative h-6 w-6">
          {/* center dot */}
          <div
            className="absolute left-1/2 top-1/2 h-[2px] w-[2px] -translate-x-1/2 -translate-y-1/2"
            style={{ background: mode === 'clickable' ? cyan : '#fff' }}
          />
          {/* four brackets */}
          {brackets.map((b, i) => (
            <div
              key={i}
              className={`absolute h-1.5 w-1.5 ${b.c}`}
              style={{
                borderColor: brColor,
                [b.b.includes('Top') ? 'borderTopWidth' : 'borderBottomWidth']: '1px',
                [b.b.includes('Left') ? 'borderLeftWidth' : 'borderRightWidth']: '1px',
                transform: `translate(${b.tx}px, ${b.ty}px)`,
                transition: 'transform 140ms cubic-bezier(0.16,1,0.3,1), border-color 140ms',
              }}
            />
          ))}
        </div>
      )}
    </div>
  )
}
