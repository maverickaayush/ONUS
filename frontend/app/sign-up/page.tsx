'use client'

/**
 * Hosted onboarding: INITIALIZE PROTOCOL (register) -> SIGNATURE HANDSHAKE
 * (email OTP) -> DASHBOARD. Domain ownership is NOT part of onboarding — a
 * verified user reaches the dashboard immediately and only proves target
 * ownership later, when they request a FULL VAPT scan (see TargetClearance).
 */
import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import {
  ApiError,
  getMe,
  resendOtp,
  signup,
  verifyOtp,
} from '@/lib/api'
import {
  AuthCard,
  AuthShell,
  CardHeader,
  CtaButton,
  ErrorText,
  Field,
  LinkRow,
  OtpInput,
  PasswordField,
  ScrambleText,
  StepTransition,
  TextLink,
} from '@/components/auth-ui'

type Step = 'register' | 'otp'

function msg(e: unknown): string {
  return e instanceof ApiError ? e.message : 'Service unavailable. Please try again.'
}

export default function SignUpPage() {
  const router = useRouter()
  const [step, setStep] = useState<Step>('register')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [expiresIn, setExpiresIn] = useState(0)
  const [resendIn, setResendIn] = useState(0)

  // Already signed in? Skip straight to the dashboard.
  useEffect(() => {
    getMe().then((u) => { if (u?.next_step === 'ready') router.replace('/') }).catch(() => {})
  }, [router])

  useEffect(() => {
    if (step !== 'otp') return
    const id = window.setInterval(() => {
      setExpiresIn((s) => Math.max(0, s - 1))
      setResendIn((s) => Math.max(0, s - 1))
    }, 1000)
    return () => window.clearInterval(id)
  }, [step])

  const mmss = (s: number) =>
    `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`

  async function onRegister(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setBusy(true)
    try {
      const c = await signup(email, password)
      setExpiresIn(c.expires_in)
      setResendIn(c.resend_in)
      setStep('otp')
    } catch (err) {
      setError(msg(err))
    } finally {
      setBusy(false)
    }
  }

  async function onVerifyOtp(code: string) {
    setError('')
    setBusy(true)
    try {
      await verifyOtp(email, code)   // establishes the session
      router.replace('/')            // straight to the dashboard
    } catch (err) {
      setError(msg(err))
    } finally {
      setBusy(false)
    }
  }

  async function onResend() {
    setError('')
    try {
      const c = await resendOtp(email)
      setExpiresIn(c.expires_in)
      setResendIn(c.resend_in)
    } catch (err) {
      setError(msg(err))
    }
  }

  return (
    <AuthShell>
      <AuthCard>
        {step === 'register' ? (
          <StepTransition stepKey="register">
            <CardHeader title="Initialize Protocol" subtitle="Create your ONUS operator account." />
            <ErrorText>{error}</ErrorText>
            <form onSubmit={onRegister}>
              <Field
                label="Email"
                id="email"
                type="email"
                required
                autoComplete="email"
                placeholder="operator@domain.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
              <PasswordField
                label="Password"
                id="password"
                required
                autoComplete="new-password"
                placeholder="••••••••••"
                meter
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <CtaButton type="submit" disabled={busy}>
                {busy ? 'Initializing…' : 'Initialize Protocol'}
              </CtaButton>
            </form>
            <LinkRow>
              Existing operator? <TextLink href="/sign-in">Authenticate</TextLink>
            </LinkRow>
          </StepTransition>
        ) : (
          <StepTransition stepKey="otp">
            <CardHeader
              title="Signature Handshake"
              subtitle={`A six-digit code was sent to ${email}.`}
            />
            <ErrorText>{error}</ErrorText>
            {busy ? (
              <div className="mb-4 py-2">
                <ScrambleText text="RESOLVING SIGNATURE..." active={busy} />
              </div>
            ) : (
              <OtpInput onComplete={onVerifyOtp} disabled={busy} />
            )}
            <div className="flex items-center justify-between font-mono text-[11px] text-white/40">
              <span>
                SECURE_HANDSHAKE_WINDOW:{' '}
                <span style={{ color: expiresIn > 0 ? '#00F0FF' : '#FF0055' }}>{mmss(expiresIn)}</span>
              </span>
              <button
                type="button"
                onClick={onResend}
                disabled={resendIn > 0}
                className="uppercase tracking-wider transition-colors enabled:hover:text-white/80 disabled:opacity-40"
              >
                {resendIn > 0 ? `Resend ${resendIn}s` : 'Resend'}
              </button>
            </div>
          </StepTransition>
        )}
      </AuthCard>
    </AuthShell>
  )
}
