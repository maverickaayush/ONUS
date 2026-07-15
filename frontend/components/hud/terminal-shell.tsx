'use client'

/**
 * Shared ONUS terminal chrome for the auth pages (/sign-in, /sign-up) so both
 * are the same security appliance: cold boot, targeting-reticle cursor, ONUS
 * emblem anchor + wireframe, brutalist card with cyan corner mounts, peripheral
 * HUD, firmware footer. Pages supply only the form as children + drive `verified`.
 */
import { ReactNode, useEffect, useRef, useState } from 'react'
import { motion } from 'motion/react'
import { OnusMark } from '@/components/ui'
import { SignalCanvas } from './signal-canvas'
import { TargetingReticle } from './targeting-reticle'
import { BootSequence } from './boot-sequence'
import { AmbientTelemetry, HexStream, TypingOscilloscope } from './hud-chrome'
import { ONUS_EMBLEM_PATH, ONUS_EMBLEM_VIEWBOX } from './emblem'

const AMBER = '#FFB000'

// AUTHENTICATE / INITIALIZE button with hover text-scramble.
const CHARS = '!<>-_\\/[]{}=+*^?#________ABCDEF0123456789'
export function ScrambleButton({ label, disabled, onClick, type = 'button' }: {
  label: string; disabled?: boolean; onClick?: () => void; type?: 'button' | 'submit'
}) {
  const [text, setText] = useState(label)
  const raf = useRef(0)
  useEffect(() => { setText(label); return () => cancelAnimationFrame(raf.current) }, [label])
  const scramble = () => {
    let frame = 0
    cancelAnimationFrame(raf.current)
    const run = () => {
      frame++
      setText(label.split('').map((c, i) => (c === ' ' ? ' ' : i < frame / 2 ? c : CHARS[Math.floor(Math.random() * CHARS.length)])).join(''))
      if (frame / 2 < label.length) raf.current = requestAnimationFrame(run)
      else setText(label)
    }
    run()
  }
  const stop = () => { cancelAnimationFrame(raf.current); setText(label) }
  return (
    <button
      type={type}
      disabled={disabled}
      onClick={onClick}
      onMouseEnter={scramble}
      onMouseLeave={stop}
      className="onus-auth-btn mt-2 w-full rounded-none py-3 font-mono text-[13px] font-600 uppercase tracking-[0.28em] transition-colors disabled:cursor-not-allowed disabled:opacity-40"
    >
      {text}
    </button>
  )
}

function CornerMounts() {
  return (
    <>
      {['left-0 top-0', 'right-0 top-0', 'left-0 bottom-0', 'right-0 bottom-0'].map((p) => (
        <span key={p} className={`absolute ${p} h-[6px] w-[6px]`} style={{ background: AMBER, boxShadow: `0 0 6px ${AMBER}` }} />
      ))}
    </>
  )
}

function EmblemHeader({ subtitle, verified }: { subtitle: string; verified?: boolean }) {
  return (
    <div className="mb-6 flex flex-col items-center">
      <div className="relative flex h-16 w-16 items-center justify-center">
        {verified && (
          <motion.span
            className="absolute inset-[-8px] rounded-full border"
            style={{ borderColor: AMBER, borderTopColor: 'transparent' }}
            initial={{ rotate: 0, opacity: 0 }}
            animate={{ rotate: 360, opacity: 1 }}
            transition={{ duration: 1.2, ease: 'linear', repeat: Infinity }}
          />
        )}
        <motion.div
          animate={verified ? { scale: [1, 1.12, 1], filter: [`drop-shadow(0 0 0px ${AMBER})`, `drop-shadow(0 0 14px ${AMBER})`, `drop-shadow(0 0 6px ${AMBER})`] } : {}}
          transition={{ duration: 1, repeat: verified ? Infinity : 0 }}
        >
          <OnusMark className="h-11 w-11" style={{ color: AMBER }} />
        </motion.div>
      </div>
      <h1 className="mt-4 font-display text-[20px] font-700 uppercase tracking-[0.32em] text-white" style={{ textShadow: '0 0 18px rgba(255,176,0,0.25)' }}>
        ONUS
      </h1>
      <p className="mt-1 font-mono text-[10px] uppercase tracking-[0.38em] text-white/40">{subtitle}</p>
    </div>
  )
}

export function TerminalShell({ subtitle, verified, children }: {
  subtitle: string; verified?: boolean; children: ReactNode
}) {
  const [booted, setBooted] = useState(false)
  return (
    <div className="onus-cursor-none relative flex min-h-screen items-center justify-center overflow-hidden px-4">
      <SignalCanvas />
      <TargetingReticle />
      <BootSequence onComplete={() => setBooted(true)} />
      <AmbientTelemetry />
      <HexStream />
      <TypingOscilloscope />

      <motion.svg
        aria-hidden="true"
        viewBox={`0 0 ${ONUS_EMBLEM_VIEWBOX} ${ONUS_EMBLEM_VIEWBOX}`}
        className="pointer-events-none fixed left-1/2 top-1/2 -z-[5] h-[130vmin] w-[130vmin] -translate-x-1/2 -translate-y-1/2"
        initial={{ opacity: 0 }}
        animate={{ opacity: [0.015, 0.03, 0.015] }}
        transition={{ duration: 14, repeat: Infinity, ease: 'easeInOut' }}
      >
        <path d={ONUS_EMBLEM_PATH} fill="none" stroke={AMBER} strokeWidth={2} />
      </motion.svg>

      <motion.div
        className="relative z-10 w-full max-w-[420px]"
        initial={{ opacity: 0, y: 10 }}
        animate={booted ? { opacity: 1, y: 0 } : { opacity: 0, y: 10 }}
        transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
      >
        <EmblemHeader subtitle={subtitle} verified={verified} />
        <div className="relative rounded-none border p-7 backdrop-blur-xl" style={{ background: 'rgba(0,0,0,0.2)', borderColor: '#222222' }}>
          <CornerMounts />
          {children}
        </div>
      </motion.div>

      <p className="pointer-events-none fixed bottom-2 left-2 z-20 font-mono text-white/25" style={{ fontSize: '8px' }}>
        Developed by maverickaayush | Report by ONUS
      </p>
    </div>
  )
}

export function TerminalError({ children }: { children: ReactNode }) {
  if (!children) return null
  return (
    <p role="alert" className="mb-4 rounded-none px-3 py-2 font-mono text-[11px]" style={{ background: 'rgba(255,0,85,0.08)', border: '1px solid rgba(255,0,85,0.25)', color: '#FF0055' }}>
      {children}
    </p>
  )
}
