'use client'

/**
 * ONUS AUTHENTICATION TERMINAL — a reactive HUD sign-in. Cold boot -> emblem
 * fade-in -> brutalist hardware card. Wired to the real auth backend (login +
 * inline OTP for an unverified email); on success the ONUS emblem enters a
 * "verified" state (cyan pulse + rotating perimeter ring) before routing.
 */
import { useEffect, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import { motion } from 'motion/react'
import { ApiError, login, verifyOtp } from '@/lib/api'
import { OnusMark } from '@/components/ui'
import { OnusCanvas } from '@/components/hud/onus-canvas'
import { TargetingReticle } from '@/components/hud/targeting-reticle'
import { BootSequence } from '@/components/hud/boot-sequence'
import { AmbientTelemetry, HexStream, TypingOscilloscope } from '@/components/hud/hud-chrome'
import { KineticField, KineticPassword } from '@/components/hud/hud-input'
import { ONUS_EMBLEM_PATH, ONUS_EMBLEM_VIEWBOX } from '@/components/hud/emblem'
import { OtpInput } from '@/components/auth-ui'

const CYAN = '#00F0FF'
const CRIMSON = '#FF0055'

function msg(e: unknown): string {
  return e instanceof ApiError ? e.message : 'LINK FAILURE — backend unreachable.'
}

// AUTHENTICATE button with hover text-scramble.
const CHARS = '!<>-_\\/[]{}=+*^?#________ABCDEF0123456789'
function ScrambleButton({ label, disabled, onClick, type = 'button' }: {
  label: string; disabled?: boolean; onClick?: () => void; type?: 'button' | 'submit'
}) {
  const [text, setText] = useState(label)
  const raf = useRef(0)
  useEffect(() => setText(label), [label])
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
  const pos = ['left-0 top-0', 'right-0 top-0', 'left-0 bottom-0', 'right-0 bottom-0']
  return (
    <>
      {pos.map((p) => (
        <span key={p} className={`absolute ${p} h-[6px] w-[6px]`} style={{ background: CYAN, boxShadow: `0 0 6px ${CYAN}` }} />
      ))}
    </>
  )
}

export default function SignInTerminal() {
  const router = useRouter()
  const [booted, setBooted] = useState(false)
  const [phase, setPhase] = useState<'login' | 'otp' | 'verified'>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  function succeed() {
    setPhase('verified')
    window.setTimeout(() => router.replace('/'), 1600)
  }

  async function onLogin(e: React.FormEvent) {
    e.preventDefault()
    setError(''); setBusy(true)
    try {
      const user = await login(email, password)
      if (user.next_step === 'verify_email') setPhase('otp')
      else succeed()
    } catch (err) { setError(msg(err)) } finally { setBusy(false) }
  }

  async function onOtp(code: string) {
    setError(''); setBusy(true)
    try { await verifyOtp(email, code); succeed() }
    catch (err) { setError(msg(err)) } finally { setBusy(false) }
  }

  return (
    <div className="onus-cursor-none relative flex min-h-screen items-center justify-center overflow-hidden px-4">
      <OnusCanvas />
      <TargetingReticle />
      <BootSequence onComplete={() => setBooted(true)} />
      <AmbientTelemetry />
      <HexStream />
      <TypingOscilloscope />

      {/* massive ultra-low-opacity wireframe emblem behind the card */}
      <motion.svg
        aria-hidden="true"
        viewBox={`0 0 ${ONUS_EMBLEM_VIEWBOX} ${ONUS_EMBLEM_VIEWBOX}`}
        className="pointer-events-none fixed left-1/2 top-1/2 -z-[5] h-[130vmin] w-[130vmin] -translate-x-1/2 -translate-y-1/2"
        initial={{ opacity: 0 }}
        animate={{ opacity: [0.015, 0.03, 0.015] }}
        transition={{ duration: 14, repeat: Infinity, ease: 'easeInOut' }}
      >
        <path d={ONUS_EMBLEM_PATH} fill="none" stroke={CYAN} strokeWidth={2} />
      </motion.svg>

      <motion.div
        className="relative z-10 w-full max-w-[420px]"
        initial={{ opacity: 0, y: 10 }}
        animate={booted ? { opacity: 1, y: 0 } : { opacity: 0, y: 10 }}
        transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
      >
        {/* Emblem anchor + verified state */}
        <div className="mb-6 flex flex-col items-center">
          <div className="relative flex h-16 w-16 items-center justify-center">
            {phase === 'verified' && (
              <motion.span
                className="absolute inset-[-8px] rounded-full border"
                style={{ borderColor: CYAN, borderTopColor: 'transparent' }}
                initial={{ rotate: 0, opacity: 0 }}
                animate={{ rotate: 360, opacity: 1 }}
                transition={{ duration: 1.2, ease: 'linear', repeat: Infinity }}
              />
            )}
            <motion.div
              animate={phase === 'verified' ? { scale: [1, 1.12, 1], filter: [`drop-shadow(0 0 0px ${CYAN})`, `drop-shadow(0 0 14px ${CYAN})`, `drop-shadow(0 0 6px ${CYAN})`] } : {}}
              transition={{ duration: 1, repeat: phase === 'verified' ? Infinity : 0 }}
            >
              <OnusMark className="h-11 w-11" style={{ color: CYAN }} />
            </motion.div>
          </div>
          <h1 className="mt-4 font-display text-[20px] font-700 uppercase tracking-[0.32em] text-white" style={{ textShadow: `0 0 18px rgba(0,240,255,0.25)` }}>
            ONUS
          </h1>
          <p className="mt-1 font-mono text-[10px] uppercase tracking-[0.38em] text-white/40">
            Authentication Terminal
          </p>
        </div>

        {/* Brutalist hardware card */}
        <div className="relative rounded-none border p-7 backdrop-blur-xl" style={{ background: 'rgba(0,0,0,0.4)', borderColor: 'rgba(255,255,255,0.1)' }}>
          <CornerMounts />

          {error && (
            <p role="alert" className="mb-4 rounded-none px-3 py-2 font-mono text-[11px]" style={{ background: 'rgba(255,0,85,0.08)', border: `1px solid rgba(255,0,85,0.25)`, color: CRIMSON }}>
              {error}
            </p>
          )}

          {phase === 'verified' ? (
            <div className="py-6 text-center">
              <p className="font-mono text-[12px] uppercase tracking-[0.3em]" style={{ color: CYAN }}>Access Granted</p>
              <p className="mt-2 font-mono text-[10px] text-white/40">Routing to command center…</p>
            </div>
          ) : phase === 'otp' ? (
            <form onSubmit={(e) => e.preventDefault()}>
              <p className="mb-4 font-mono text-[11px] leading-relaxed text-white/45">
                IDENTITY UNVERIFIED · signature code dispatched to {email}.
              </p>
              <OtpInput onComplete={onOtp} disabled={busy} />
            </form>
          ) : (
            <form onSubmit={onLogin}>
              <KineticField label="Operator ID" id="email" type="email" required autoComplete="email" placeholder="operator@domain.com" value={email} onChange={(e) => setEmail(e.target.value)} />
              <KineticPassword label="Passphrase" id="password" required placeholder="••••••••••" value={password} onChange={(e) => setPassword(e.target.value)} />
              <ScrambleButton type="submit" label={busy ? 'AUTHENTICATING' : 'AUTHENTICATE'} disabled={busy} />
              <p className="mt-5 text-center font-mono text-[11px] text-white/35">
                NO CREDENTIALS? <a href="/sign-up" style={{ color: CYAN }}>INITIALIZE ACCOUNT</a>
              </p>
            </form>
          )}
        </div>
      </motion.div>

      {/* firmware-registry footer */}
      <p className="pointer-events-none fixed bottom-2 left-2 z-20 font-mono text-white/25" style={{ fontSize: '8px' }}>
        Developed by maverickaayush | Report by ONUS
      </p>
    </div>
  )
}
