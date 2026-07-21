'use client'

/**
 * Target authorization overlay — shown when a FULL VAPT scan hits the backend's
 * TARGET_AUTHORIZATION_REQUIRED gate. Proves ownership of ONE target (meta tag
 * or HTTP file), then hands control back so the pending scan can auto-retry.
 * This is target authorization, NOT identity onboarding — deliberately concise.
 */
import { useEffect, useRef, useState } from 'react'
import {
  ApiError,
  checkDomainChallenge,
  DomainChallenge,
  issueDomainChallenge,
} from '@/lib/api'
import {
  CopyButton,
  CtaButton,
  ErrorText,
  ResolverLog,
} from '@/components/auth-ui'

const RESOLVER_LINES = [
  '> INITIALIZING RESOLVER',
  '> NORMALIZING TARGET',
  '> QUERYING AUTHORITATIVE RECORD',
  '> COMPARING CHALLENGE SIGNATURE',
  '> WAITING FOR RESOLVER RESPONSE',
]

function msg(e: unknown): string {
  return e instanceof ApiError ? e.message : 'Service unavailable. Please try again.'
}

export function TargetClearance({
  target,
  onVerified,
  onClose,
}: {
  target: string
  onVerified: () => void
  onClose: () => void
}) {
  const [method, setMethod] = useState<'meta_tag' | 'http_file'>('meta_tag')
  const [challenge, setChallenge] = useState<DomainChallenge | null>(null)
  const [error, setError] = useState('')
  const [resolving, setResolving] = useState(false)
  const [done, setDone] = useState(false)

  // Issue (or re-issue on method change) the backend challenge.
  const lastMethod = useRef<string>('')
  useEffect(() => {
    if (lastMethod.current === method && challenge) return
    lastMethod.current = method
    issueDomainChallenge(target, method)
      .then(setChallenge)
      .catch((e) => setError(msg(e)))
  }, [method, target, challenge])

  async function onVerify() {
    if (!challenge) return
    setError('')
    setResolving(true)
    const started = Date.now()
    try {
      const res = await checkDomainChallenge(challenge.verification_id)
      await new Promise((r) => setTimeout(r, Math.max(0, 1800 - (Date.now() - started))))
      if (res.verified) {
        setDone(true)
        window.setTimeout(onVerified, 1200)
      } else {
        setError(res.detail || 'Verification failed. Check the record and try again.')
      }
    } catch (e) {
      setError(msg(e))
    } finally {
      setResolving(false)
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center px-4"
      style={{ background: 'rgba(2,2,8,0.72)', backdropFilter: 'blur(4px)' }}
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-[440px] rounded-[10px] px-7 py-7 backdrop-blur-xl"
        style={{ background: 'rgba(3,3,7,0.85)', border: '1px solid rgba(0,240,255,0.12)' }}
      >
        {done ? (
          <div className="py-6 text-center">
            <div
              className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full"
              style={{ background: 'rgba(0,240,255,0.1)', border: '1px solid rgba(0,240,255,0.4)' }}
            >
              <span style={{ color: '#00F0FF', fontSize: 22 }}>✓</span>
            </div>
            <h2 className="font-display text-[14px] font-600 uppercase tracking-[0.16em] text-white">
              Target Authorized
            </h2>
            <p className="mt-2 font-mono text-[12px]" style={{ color: '#00F0FF' }}>
              ACTIVE SCANNING UNLOCKED
            </p>
            <p className="mt-1 font-mono text-[11px] text-white/40">Resuming your scan…</p>
          </div>
        ) : (
          <>
            <h2 className="font-display text-[14px] font-600 uppercase tracking-[0.16em] text-white">
              Unlock Active Scanning
            </h2>
            <p className="mt-2 text-[13px] leading-relaxed text-white/45">
              Active reconnaissance and attack-surface testing require authorization for this target.
            </p>
            <div className="mt-4 mb-4">
              <span className="font-mono text-[11px] uppercase tracking-wider text-white/40">Target</span>
              <div className="mt-1 font-mono text-[15px]" style={{ color: '#00F0FF' }}>{target}</div>
            </div>

            <ErrorText>{error}</ErrorText>

            <div className="mb-3 flex gap-2">
              {(['meta_tag', 'http_file'] as const).map((m) => (
                <button
                  key={m}
                  type="button"
                  onClick={() => { setChallenge(null); setMethod(m) }}
                  className="flex-1 rounded-[5px] px-2 py-1.5 font-mono text-[11px] uppercase tracking-wider transition-colors"
                  style={
                    method === m
                      ? { background: 'rgba(0,240,255,0.12)', border: '1px solid rgba(0,240,255,0.4)', color: '#00F0FF' }
                      : { border: '1px solid rgba(255,255,255,0.06)', color: 'rgba(255,255,255,0.4)' }
                  }
                >
                  {m === 'meta_tag' ? 'Meta Tag · Recommended' : 'HTTP File'}
                </button>
              ))}
            </div>

            {challenge && <Challenge method={method} challenge={challenge} target={target} />}

            <ResolverLog lines={RESOLVER_LINES} active={resolving} />
            <CtaButton type="button" onClick={onVerify} disabled={resolving || !challenge}>
              {resolving ? 'Resolving…' : 'Verify Target'}
            </CtaButton>
            <button
              type="button"
              onClick={onClose}
              className="mt-3 w-full text-center font-mono text-[11px] text-white/35 transition-colors hover:text-white/60"
            >
              Cancel
            </button>
          </>
        )}
      </div>
    </div>
  )
}

function Challenge({
  method,
  challenge,
  target,
}: {
  method: 'meta_tag' | 'http_file'
  challenge: DomainChallenge
  target: string
}) {
  const box = {
    background: 'rgba(0,0,0,0.4)',
    border: '1px solid rgba(255,255,255,0.05)',
  } as const
  if (method === 'meta_tag') {
    return (
      <div className="mb-3">
        <p className="mb-2 font-mono text-[11px] uppercase tracking-wider text-white/40">
          Add inside your homepage &lt;head&gt;, publish, then verify
        </p>
        <div className="flex items-start gap-2 rounded-[5px] p-3 font-mono text-[11px] leading-relaxed" style={box}>
          <code className="flex-1 break-all text-white/70">{challenge.meta_tag}</code>
          <CopyButton value={challenge.meta_tag} />
        </div>
      </div>
    )
  }
  return (
    <div className="mb-3">
      <p className="mb-2 font-mono text-[11px] uppercase tracking-wider text-white/40">
        Host this file, then verify
      </p>
      <div className="rounded-[5px] p-3 font-mono text-[11px] leading-relaxed" style={box}>
        <div className="mb-2 flex items-start gap-2">
          <code className="flex-1 break-all text-white/50">https://{target}{challenge.file_path}</code>
          <CopyButton value={`https://${target}${challenge.file_path}`} />
        </div>
        <div className="flex items-start gap-2 border-t border-white/5 pt-2">
          <code className="flex-1 break-all text-white/70">{challenge.file_contents}</code>
          <CopyButton value={challenge.file_contents} />
        </div>
      </div>
    </div>
  )
}
