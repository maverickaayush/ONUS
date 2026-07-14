'use client'

import { useEffect, useRef, useState } from 'react'
import { OnusMark } from './ui'

// Two large softly-blurred accent fields plus one that is the Onus emblem
// blurred so far back it reads as atmosphere, not branding (never legible as the
// logo - that's the bar). All three drift on their own timelines AND take a few
// px of cursor parallax so the space feels alive rather than looped.
// Drift is neutralized for reduced-motion by the global CSS rule; the cursor
// parallax is a JS listener, so it's gated separately here.
export function AmbientBackground() {
  const rootRef = useRef<HTMLDivElement>(null)
  const [reduced, setReduced] = useState(false)

  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    setReduced(mq.matches)
    const on = () => setReduced(mq.matches)
    mq.addEventListener('change', on)
    return () => mq.removeEventListener('change', on)
  }, [])

  useEffect(() => {
    const el = rootRef.current
    if (!el) return
    if (reduced) {
      el.style.setProperty('--mx', '0')
      el.style.setProperty('--my', '0')
      return
    }
    let raf = 0
    const onMove = (e: MouseEvent) => {
      cancelAnimationFrame(raf)
      raf = requestAnimationFrame(() => {
        el.style.setProperty('--mx', ((e.clientX / window.innerWidth) * 2 - 1).toFixed(3))
        el.style.setProperty('--my', ((e.clientY / window.innerHeight) * 2 - 1).toFixed(3))
      })
    }
    window.addEventListener('mousemove', onMove)
    return () => {
      window.removeEventListener('mousemove', onMove)
      cancelAnimationFrame(raf)
    }
  }, [reduced])

  const glide = { transition: 'transform 0.5s ease-out' }

  return (
    <div ref={rootRef} aria-hidden className="pointer-events-none fixed inset-0 -z-10 overflow-hidden">
      <div className="absolute inset-0 bg-canvas" />

      <div
        className="absolute -left-[10%] top-[-15%] h-[55vmax] w-[55vmax]"
        style={{ transform: 'translate(calc(var(--mx,0) * 12px), calc(var(--my,0) * 12px))', ...glide }}
      >
        <div
          className="h-full w-full rounded-full"
          style={{
            background: 'radial-gradient(circle, rgba(38,224,245,0.10), transparent 62%)',
            filter: 'blur(60px)',
            animation: 'onus-drift-a 34s ease-in-out infinite',
          }}
        />
      </div>

      <div
        className="absolute bottom-[-20%] right-[-10%] h-[50vmax] w-[50vmax]"
        style={{ transform: 'translate(calc(var(--mx,0) * -9px), calc(var(--my,0) * -9px))', ...glide }}
      >
        <div
          className="h-full w-full rounded-full"
          style={{
            background: 'radial-gradient(circle, rgba(26,169,189,0.09), transparent 60%)',
            filter: 'blur(70px)',
            animation: 'onus-drift-b 42s ease-in-out infinite',
          }}
        />
      </div>

      {/* Emblem silhouette - blurred far past legibility into pure field */}
      <div
        className="absolute left-[36%] top-[30%] h-[42vmax] w-[42vmax]"
        style={{ transform: 'translate(calc(var(--mx,0) * 6px), calc(var(--my,0) * 6px))', ...glide }}
      >
        <div
          className="flex h-full w-full items-center justify-center"
          style={{ filter: 'blur(48px)', opacity: 0.16, animation: 'onus-drift-a 50s ease-in-out infinite' }}
        >
          <OnusMark className="h-full w-full text-accent" />
        </div>
      </div>
    </div>
  )
}
