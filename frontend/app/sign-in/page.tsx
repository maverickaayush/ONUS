'use client'

/** Existing-operator authentication. On success the backend sets a secure
 * HttpOnly session cookie; we then route by the returned verification state.
 * An unverified email drops into the same OTP handshake as signup. */
import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { ApiError, login, verifyOtp } from '@/lib/api'
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

function msg(e: unknown): string {
  if (e instanceof ApiError) return e.message
  return 'Service unavailable. Please try again.'
}

export default function SignInPage() {
  const router = useRouter()
  const [phase, setPhase] = useState<'login' | 'otp'>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  function route(_nextStep: string) {
    // Domain ownership is no longer part of onboarding, so a verified login
    // always lands on the dashboard; an unverified email is handled by the
    // 'otp' phase before this is reached.
    router.replace('/')
  }

  async function onLogin(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setBusy(true)
    try {
      const user = await login(email, password)
      if (user.next_step === 'verify_email') setPhase('otp')
      else route(user.next_step)
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
      const user = await verifyOtp(email, code)
      route(user.next_step)
    } catch (err) {
      setError(msg(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <AuthShell>
      <AuthCard>
        {phase === 'login' ? (
          <StepTransition stepKey="login">
            <CardHeader title="Authenticate" subtitle="Resume secure ONUS session." />
            <ErrorText>{error}</ErrorText>
            <form onSubmit={onLogin}>
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
                autoComplete="current-password"
                placeholder="••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <CtaButton type="submit" disabled={busy}>
                {busy ? 'Authenticating…' : 'Authenticate'}
              </CtaButton>
            </form>
            <LinkRow>
              New operator? <TextLink href="/sign-up">Initialize an account</TextLink>
            </LinkRow>
          </StepTransition>
        ) : (
          <StepTransition stepKey="otp">
            <CardHeader
              title="Signature Handshake"
              subtitle={`Your email needs verification. A code was sent to ${email}.`}
            />
            <ErrorText>{error}</ErrorText>
            {busy ? (
              <div className="mb-4 py-2">
                <ScrambleText text="RESOLVING SIGNATURE..." active={busy} />
              </div>
            ) : (
              <OtpInput onComplete={onVerifyOtp} disabled={busy} />
            )}
          </StepTransition>
        )}
      </AuthCard>
    </AuthShell>
  )
}
