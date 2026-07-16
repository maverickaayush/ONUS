'use client'

/**
 * ONUS AUTHENTICATION TERMINAL — reactive HUD sign-in (shared TerminalShell).
 * Wired to the real backend: login + inline OTP for an unverified email; on
 * success the emblem enters its "verified" state before routing to the dashboard.
 */
import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { ApiError, login, verifyOtp } from '@/lib/api'
import { ScrambleButton, TerminalError, TerminalShell } from '@/components/hud/terminal-shell'
import { KineticField, KineticPassword } from '@/components/hud/hud-input'
import { OAuthButtons } from '@/components/hud/oauth-buttons'
import { OtpInput } from '@/components/auth-ui'
import { HostingNotice } from '@/components/hosting-notice'

const CYAN = '#00F0FF'
const msg = (e: unknown) => (e instanceof ApiError ? e.message : 'LINK FAILURE — backend unreachable.')

export default function SignInTerminal() {
  const router = useRouter()
  const [phase, setPhase] = useState<'login' | 'otp' | 'verified'>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  // OAuth callback bounced back with a failure.
  useEffect(() => {
    if (new URLSearchParams(window.location.search).get('error') === 'oauth') {
      setError('Provider sign-in failed. Try again, or use email + passphrase.')
    }
  }, [])

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
    <TerminalShell subtitle="Authentication Terminal" verified={phase === 'verified'}>
      <TerminalError>{error}</TerminalError>
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
        <>
          <OAuthButtons />
          <form onSubmit={onLogin}>
            <KineticField label="Operator ID" id="email" type="email" required autoComplete="email" placeholder="operator@domain.com" value={email} onChange={(e) => setEmail(e.target.value)} />
            <KineticPassword label="Passphrase" id="password" required placeholder="••••••••••" value={password} onChange={(e) => setPassword(e.target.value)} />
            <ScrambleButton type="submit" label={busy ? 'AUTHENTICATING' : 'AUTHENTICATE'} disabled={busy} />
            <p className="mt-5 text-center font-mono text-[11px] text-white/35">
              NO CREDENTIALS? <a href="/sign-up" style={{ color: CYAN }}>INITIALIZE ACCOUNT</a>
            </p>
          </form>
          <HostingNotice />
        </>
      )}
    </TerminalShell>
  )
}
