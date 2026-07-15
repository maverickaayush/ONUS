'use client'

/**
 * Hosted clearance sequence: INITIALIZE PROTOCOL (register) -> SIGNATURE
 * HANDSHAKE (email OTP) -> DOMAIN VALIDATION (ownership). Every transition is
 * driven by a real backend response — no timers stand in for success.
 */
import { useEffect, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import {
  ApiError,
  checkDomainChallenge,
  DomainChallenge,
  getMe,
  issueDomainChallenge,
  resendOtp,
  signup,
  verifyOtp,
} from '@/lib/api'
import {
  AuthCard,
  AuthShell,
  CardHeader,
  CopyButton,
  CtaButton,
  ErrorText,
  Field,
  LinkRow,
  OtpInput,
  PasswordField,
  ResolverLog,
  ScrambleText,
  StepTransition,
  TextLink,
} from '@/components/auth-ui'

type Step = 'register' | 'otp' | 'domain' | 'done'

const RESOLVER_LINES = [
  '> INITIALIZING RESOLVER',
  '> NORMALIZING TARGET',
  '> QUERYING AUTHORITATIVE RECORD',
  '> COMPARING CHALLENGE SIGNATURE',
  '> WAITING FOR RESOLVER RESPONSE',
]

function msg(e: unknown): string {
  if (e instanceof ApiError) return e.message
  return 'Service unavailable. Please try again.'
}

export default function SignUpPage() {
  const router = useRouter()
  const [step, setStep] = useState<Step>('register')
  const [error, setError] = useState<string>('')
  const [busy, setBusy] = useState(false)

  // register
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')

  // otp
  const [expiresIn, setExpiresIn] = useState(0)
  const [resendIn, setResendIn] = useState(0)

  // domain
  const [domain, setDomain] = useState('')
  const [method, setMethod] = useState<'meta_tag' | 'http_file'>('meta_tag')
  const [challenge, setChallenge] = useState<DomainChallenge | null>(null)
  const [resolving, setResolving] = useState(false)

  // Resume an in-progress account (verified email but no domain, etc.).
  useEffect(() => {
    getMe()
      .then((u) => {
        if (!u) return
        if (u.next_step === 'ready') router.replace('/')
        else if (u.next_step === 'verify_domain') {
          setEmail(u.email)
          setStep('domain')
        }
      })
      .catch(() => {})
  }, [router])

  // countdowns
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
      const user = await verifyOtp(email, code)
      if (user.next_step === 'ready') router.replace('/')
      else setStep('domain')
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

  async function onIssueChallenge(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setBusy(true)
    try {
      setChallenge(await issueDomainChallenge(domain, method))
    } catch (err) {
      setError(msg(err))
    } finally {
      setBusy(false)
    }
  }

  async function onVerifyDomain() {
    if (!challenge) return
    setError('')
    setResolving(true)
    const started = Date.now()
    try {
      const res = await checkDomainChallenge(challenge.verification_id)
      // brief minimum so the resolver log doesn't flash; success still depends
      // entirely on the real backend result.
      const wait = Math.max(0, 1800 - (Date.now() - started))
      await new Promise((r) => setTimeout(r, wait))
      if (res.verified) {
        setStep('done')
        window.setTimeout(() => router.replace('/'), 1400)
      } else {
        setError(res.detail || 'Verification failed. Check the record and try again.')
      }
    } catch (err) {
      setError(msg(err))
    } finally {
      setResolving(false)
    }
  }

  // re-issue the challenge when the method tab changes (token differs per method)
  const methodRef = useRef(method)
  useEffect(() => {
    if (methodRef.current !== method && challenge && domain) {
      methodRef.current = method
      issueDomainChallenge(domain, method).then(setChallenge).catch(() => {})
    } else {
      methodRef.current = method
    }
  }, [method, challenge, domain])

  return (
    <AuthShell>
      <AuthCard>
        {step === 'register' && (
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
        )}

        {step === 'otp' && (
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

        {step === 'domain' && (
          <StepTransition stepKey="domain">
            <CardHeader
              title="Domain Validation"
              subtitle="Prove control of a domain to authorize scans against it and its subdomains."
            />
            <ErrorText>{error}</ErrorText>
            <form onSubmit={onIssueChallenge}>
              <Field
                label="Target Domain"
                id="domain"
                required
                placeholder="target.com"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                disabled={!!challenge}
              />
              {!challenge && (
                <CtaButton type="submit" disabled={busy}>
                  {busy ? 'Issuing challenge…' : 'Generate Challenge'}
                </CtaButton>
              )}
            </form>

            {challenge && (
              <>
                <div className="mb-3 mt-1 flex gap-2">
                  {(['meta_tag', 'http_file'] as const).map((m) => (
                    <button
                      key={m}
                      type="button"
                      onClick={() => setMethod(m)}
                      className="flex-1 rounded-[5px] px-2 py-1.5 font-mono text-[11px] uppercase tracking-wider transition-colors"
                      style={
                        method === m
                          ? { background: 'rgba(0,240,255,0.12)', border: '1px solid rgba(0,240,255,0.4)', color: '#00F0FF' }
                          : { border: '1px solid rgba(255,255,255,0.06)', color: 'rgba(255,255,255,0.4)' }
                      }
                    >
                      {m === 'meta_tag' ? 'Meta Tag' : 'HTTP File'}
                    </button>
                  ))}
                </div>

                <ChallengeBlock method={method} challenge={challenge} domain={domain} />

                <ResolverLog lines={RESOLVER_LINES} active={resolving} />
                <CtaButton type="button" onClick={onVerifyDomain} disabled={resolving}>
                  {resolving ? 'Resolving…' : 'Run Resolver & Activate'}
                </CtaButton>
              </>
            )}
          </StepTransition>
        )}

        {step === 'done' && (
          <StepTransition stepKey="done">
            <div className="py-6 text-center">
              <div
                className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full"
                style={{ background: 'rgba(0,240,255,0.1)', border: '1px solid rgba(0,240,255,0.4)' }}
              >
                <span style={{ color: '#00F0FF', fontSize: 22 }}>✓</span>
              </div>
              <h1 className="font-display text-[15px] font-600 uppercase tracking-[0.18em] text-white">
                Clearance Granted
              </h1>
              <p className="mt-2 font-mono text-[12px] text-white/45">
                Ownership of {domain} verified. Redirecting to console…
              </p>
            </div>
          </StepTransition>
        )}
      </AuthCard>
    </AuthShell>
  )
}

function ChallengeBlock({
  method,
  challenge,
  domain,
}: {
  method: 'meta_tag' | 'http_file'
  challenge: DomainChallenge
  domain: string
}) {
  if (method === 'meta_tag') {
    return (
      <div className="mb-3">
        <p className="mb-2 font-mono text-[11px] uppercase tracking-wider text-white/40">
          Add to your homepage &lt;head&gt;
        </p>
        <div
          className="flex items-start gap-2 rounded-[5px] p-3 font-mono text-[11px] leading-relaxed"
          style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(255,255,255,0.05)' }}
        >
          <code className="flex-1 break-all text-white/70">{challenge.meta_tag}</code>
          <CopyButton value={challenge.meta_tag} />
        </div>
      </div>
    )
  }
  return (
    <div className="mb-3">
      <p className="mb-2 font-mono text-[11px] uppercase tracking-wider text-white/40">
        Host this file
      </p>
      <div
        className="rounded-[5px] p-3 font-mono text-[11px] leading-relaxed"
        style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(255,255,255,0.05)' }}
      >
        <div className="mb-2 flex items-start gap-2">
          <code className="flex-1 break-all text-white/50">
            https://{domain}
            {challenge.file_path}
          </code>
          <CopyButton value={`https://${domain}${challenge.file_path}`} />
        </div>
        <div className="flex items-start gap-2 border-t border-white/5 pt-2">
          <code className="flex-1 break-all text-white/70">{challenge.file_contents}</code>
          <CopyButton value={challenge.file_contents} />
        </div>
      </div>
    </div>
  )
}
