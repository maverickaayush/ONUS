'use client'

/**
 * ONUS INITIALIZATION TERMINAL — HUD sign-up (shared TerminalShell), matching
 * the sign-in terminal. Flow: register -> email OTP -> dashboard. Domain
 * ownership is NOT part of onboarding. On verify, the emblem enters its
 * "verified" state before routing.
 */
import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { ApiError, getMe, resendOtp, signup, verifyOtp } from '@/lib/api'
import { ScrambleButton, TerminalError, TerminalShell } from '@/components/hud/terminal-shell'
import { KineticField, KineticPassword } from '@/components/hud/hud-input'
import { OtpInput, passwordScore } from '@/components/auth-ui'

const CYAN = '#00F0FF'
const msg = (e: unknown) => (e instanceof ApiError ? e.message : 'LINK FAILURE — backend unreachable.')

function SecurityMeter({ value }: { value: string }) {
  const score = passwordScore(value)
  return (
    <div className="mb-5 mt-[-8px] flex gap-1.5" aria-hidden="true">
      {[0, 1, 2, 3, 4].map((i) => (
        <span key={i} className="h-[3px] flex-1 rounded-none transition-colors duration-200"
          style={{ background: i < score ? CYAN : 'rgba(255,255,255,0.08)', boxShadow: i < score ? `0 0 6px ${CYAN}` : 'none' }} />
      ))}
    </div>
  )
}

export default function SignUpTerminal() {
  const router = useRouter()
  const [phase, setPhase] = useState<'register' | 'otp' | 'verified'>('register')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [expiresIn, setExpiresIn] = useState(0)
  const [resendIn, setResendIn] = useState(0)

  useEffect(() => {
    getMe().then((u) => { if (u?.next_step === 'ready') router.replace('/') }).catch(() => {})
  }, [router])

  useEffect(() => {
    if (phase !== 'otp') return
    const id = window.setInterval(() => {
      setExpiresIn((s) => Math.max(0, s - 1))
      setResendIn((s) => Math.max(0, s - 1))
    }, 1000)
    return () => window.clearInterval(id)
  }, [phase])

  const mmss = (s: number) => `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`

  async function onRegister(e: React.FormEvent) {
    e.preventDefault()
    setError(''); setBusy(true)
    try {
      const c = await signup(email, password)
      setExpiresIn(c.expires_in); setResendIn(c.resend_in)
      setPhase('otp')
    } catch (err) { setError(msg(err)) } finally { setBusy(false) }
  }

  async function onOtp(code: string) {
    setError(''); setBusy(true)
    try {
      await verifyOtp(email, code)
      setPhase('verified')
      window.setTimeout(() => router.replace('/'), 1600)
    } catch (err) { setError(msg(err)) } finally { setBusy(false) }
  }

  async function onResend() {
    setError('')
    try { const c = await resendOtp(email); setExpiresIn(c.expires_in); setResendIn(c.resend_in) }
    catch (err) { setError(msg(err)) }
  }

  return (
    <TerminalShell subtitle="Initialization Terminal" verified={phase === 'verified'}>
      <TerminalError>{error}</TerminalError>
      {phase === 'verified' ? (
        <div className="py-6 text-center">
          <p className="font-mono text-[12px] uppercase tracking-[0.3em]" style={{ color: CYAN }}>Clearance Granted</p>
          <p className="mt-2 font-mono text-[10px] text-white/40">Routing to command center…</p>
        </div>
      ) : phase === 'otp' ? (
        <form onSubmit={(e) => e.preventDefault()}>
          <p className="mb-4 font-mono text-[11px] leading-relaxed text-white/45">
            SIGNATURE HANDSHAKE · six-digit code dispatched to {email}.
          </p>
          <OtpInput onComplete={onOtp} disabled={busy} />
          <div className="flex items-center justify-between font-mono text-[10px] text-white/40">
            <span>WINDOW: <span style={{ color: expiresIn > 0 ? CYAN : '#FF0055' }}>{mmss(expiresIn)}</span></span>
            <button type="button" onClick={onResend} disabled={resendIn > 0}
              className="uppercase tracking-wider transition-colors enabled:hover:text-white/80 disabled:opacity-40">
              {resendIn > 0 ? `Resend ${resendIn}s` : 'Resend'}
            </button>
          </div>
        </form>
      ) : (
        <form onSubmit={onRegister}>
          <KineticField label="Operator ID" id="email" type="email" required autoComplete="email" placeholder="operator@domain.com" value={email} onChange={(e) => setEmail(e.target.value)} />
          <KineticPassword label="Passphrase" id="password" required placeholder="••••••••••" value={password} onChange={(e) => setPassword(e.target.value)} />
          <SecurityMeter value={password} />
          <ScrambleButton type="submit" label={busy ? 'INITIALIZING' : 'INITIALIZE PROTOCOL'} disabled={busy} />
          <p className="mt-5 text-center font-mono text-[11px] text-white/35">
            EXISTING OPERATOR? <a href="/sign-in" style={{ color: CYAN }}>AUTHENTICATE</a>
          </p>
        </form>
      )}
    </TerminalShell>
  )
}
