'use client'

/**
 * BootSequence — a ~1.5s cold-boot overlay: black screen, rapid green log lines
 * top-left, then a razor-thin cyan scanline strikes across and expands vertically
 * to reveal the interface. Calls onComplete once the reveal finishes. Respects
 * prefers-reduced-motion (skips near-instantly).
 */
import { useEffect, useState } from 'react'
import { AnimatePresence, motion } from 'motion/react'

const LOGS = [
  '> ALLOCATING MEMORY...',
  '> LOADING CRYPTOGRAPHIC MODULES...',
  '> SECURING EXECUTION ENVIRONMENT...',
  '> INITIALIZING ONUS CORE...',
  '> READY',
]

export function BootSequence({ onComplete }: { onComplete: () => void }) {
  const [shown, setShown] = useState(0)
  const [phase, setPhase] = useState<'logs' | 'reveal' | 'done'>('logs')

  useEffect(() => {
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    if (reduced) { onComplete(); setPhase('done'); return }
    const timers: number[] = []
    LOGS.forEach((_, i) => timers.push(window.setTimeout(() => setShown(i + 1), 120 + i * 240)))
    timers.push(window.setTimeout(() => setPhase('reveal'), 120 + LOGS.length * 240))
    timers.push(window.setTimeout(() => { setPhase('done'); onComplete() }, 120 + LOGS.length * 240 + 650))
    return () => timers.forEach(clearTimeout)
  }, [onComplete])

  return (
    <AnimatePresence>
      {phase !== 'done' && (
        <motion.div
          className="fixed inset-0 z-[200] overflow-hidden"
          initial={{ opacity: 1 }}
          exit={{ opacity: 0 }}
        >
          {/* black shutter that splits open on reveal */}
          <motion.div
            className="absolute inset-x-0 top-0 bg-black"
            initial={{ height: '50%' }}
            animate={phase === 'reveal' ? { height: '0%' } : { height: '50%' }}
            transition={{ duration: 0.55, ease: [0.16, 1, 0.3, 1] }}
          />
          <motion.div
            className="absolute inset-x-0 bottom-0 bg-black"
            initial={{ height: '50%' }}
            animate={phase === 'reveal' ? { height: '0%' } : { height: '50%' }}
            transition={{ duration: 0.55, ease: [0.16, 1, 0.3, 1] }}
          />
          {/* the cyan scanline that strikes across at reveal */}
          {phase === 'reveal' && (
            <motion.div
              className="absolute inset-x-0 top-1/2 h-px"
              style={{ background: '#00F0FF', boxShadow: '0 0 12px 1px #00F0FF' }}
              initial={{ scaleX: 0, opacity: 1 }}
              animate={{ scaleX: 1, opacity: [1, 1, 0] }}
              transition={{ duration: 0.55, ease: 'easeOut' }}
            />
          )}
          {/* boot log */}
          <div className="absolute left-5 top-5 font-mono text-[10px] leading-relaxed" style={{ color: '#39ff88' }}>
            {LOGS.slice(0, shown).map((l, i) => (
              <div key={i} style={{ opacity: 0.85 }}>
                {l}
                {i === shown - 1 && phase === 'logs' && <span className="onus-caret">▋</span>}
              </div>
            ))}
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
