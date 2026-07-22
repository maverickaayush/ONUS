'use client'

import { useEffect, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import {
  Check,
  ChevronDown,
  CircleAlert,
  KeyRound,
  Lock,
  ShieldCheck,
  X,
} from 'lucide-react'
import {
  ApiError,
  getAuthProviders,
  getScanModules,
  submitScan,
  targetAuthorizationRequired,
  type AuthConfigWire,
  type ScanMode,
  type ScanModuleInfo,
} from '@/lib/api'
import { cn } from '@/lib/format'
import { trackEvent } from '@/lib/analytics'
import { MagneticButton, ModuleIcon, Panel, Spinner } from './ui'
import { TargetClearance } from './target-clearance'
import { HostingNotice } from './hosting-notice'
import { Plate } from './decor'

const DOMAIN_RE =
  /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/

// Parity with the live backend: public IPv4 literals are accepted; private /
// loopback / link-local ranges are rejected client-side.
function isPublicIpv4(v: string): boolean {
  const m = v.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (!m) return false
  const o = m.slice(1).map(Number)
  if (o.some((n) => n > 255)) return false
  const [a, b] = o
  if (a === 10 || a === 127 || a === 0) return false
  if (a === 192 && b === 168) return false
  if (a === 172 && b >= 16 && b <= 31) return false
  if (a === 169 && b === 254) return false
  return true
}

// Hostnames that resolve to the local machine or a private network. DOMAIN_RE
// alone accepted these (`foo.localhost` matched: labels + an alphabetic TLD), so
// the request was dispatched and only the backend refused it. The product claims
// private ranges are refused BEFORE a job is queued, so the client must hold the
// same line rather than leaving it to the server.
const BLOCKED_HOSTNAMES = ['localhost']
const BLOCKED_SUFFIXES = ['.localhost', '.local', '.internal', '.home.arpa']

function isBlockedHostname(v: string): boolean {
  const h = v.toLowerCase().replace(/\.$/, '') // tolerate a trailing FQDN dot
  return BLOCKED_HOSTNAMES.includes(h) || BLOCKED_SUFFIXES.some((sfx) => h.endsWith(sfx))
}

// IPv6 loopback (::1), unspecified (::), link-local (fe80::/10) and unique-local
// (fc00::/7). Bare IPv6 is not an accepted target today; this is a guard against
// it ever becoming one silently.
function isBlockedIpv6(v: string): boolean {
  const h = v.toLowerCase().replace(/^\[|\]$/g, '')
  if (!h.includes(':')) return false
  return h === '::1' || h === '::' || h.startsWith('fe80:') || /^f[cd][0-9a-f]{2}:/.test(h)
}

function isValidTarget(v: string): boolean {
  const t = v.trim()
  if (!t || isBlockedHostname(t) || isBlockedIpv6(t)) return false
  return DOMAIN_RE.test(t) || isPublicIpv4(t)
}

type LoginType = 'auto' | 'form' | 'json'

export function NewScan() {
  const router = useRouter()
  const [modules, setModules] = useState<ScanModuleInfo[]>([])
  const [domain, setDomain] = useState('')
  const [authorized, setAuthorized] = useState(false)
  const [loading, setLoading] = useState(false)
  const [submitError, setSubmitError] = useState<string | null>(null)
  // Scan mode + pending target-authorization overlay (hosted). Default 'full'
  // preserves the classic behavior; the backend gates active scans regardless.
  // Quick is the default: it is passive, finishes in minutes, and completes
  // unattended. Full runs the active modules and can park at an operator
  // decision if one times out, which is a poor first experience for someone
  // who just cloned the repo. Full stays one click away.
  // Product decision: the mode toggle is a HOSTED-only affordance. Self-hosted
  // is full-scan only - that operator owns the target and wants the complete
  // assessment - so no toggle renders and 'full' is submitted explicitly rather
  // than relying on the backend default, which must not be able to change this
  // behaviour silently.
  const [hosted, setHosted] = useState<boolean | null>(null)
  const [scanMode, setScanMode] = useState<ScanMode>('full')
  const [clearanceTarget, setClearanceTarget] = useState<string | null>(null)

  const [authOpen, setAuthOpen] = useState(false)
  const [loginType, setLoginType] = useState<LoginType>('auto')
  const [loginUrl, setLoginUrl] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [advancedOpen, setAdvancedOpen] = useState(false)
  const [usernameField, setUsernameField] = useState('')
  const [passwordField, setPasswordField] = useState('')
  const [tokenJsonPath, setTokenJsonPath] = useState('')

  const [checksOpen, setChecksOpen] = useState(false)

  useEffect(() => {
    getScanModules()
      .then(setModules)
      .catch(() => setModules([]))
    getAuthProviders()
      .then((p) => {
        setHosted(p.require_auth)
        // Self-hosted never offers a choice; pin the request to full.
        if (!p.require_auth) setScanMode('full')
      })
      .catch(() => setHosted(false))
  }, [])

  const domainTouched = domain.trim().length > 0
  const domainValid = isValidTarget(domain)
  const authComplete =
    loginUrl.trim() !== '' && username.trim() !== '' && password.trim() !== ''
  const canSubmit = domainValid && authorized && !loading

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!canSubmit) return
    setSubmitError(null)
    setLoading(true)

    let auth: AuthConfigWire | undefined
    if (authComplete) {
      auth = {
        login_url: loginUrl.trim(),
        username: username.trim(),
        password,
        login_type: loginType,
      }
      if (usernameField.trim()) auth.username_field = usernameField.trim()
      if (passwordField.trim()) auth.password_field = passwordField.trim()
      if (loginType === 'json' && tokenJsonPath.trim())
        auth.token_json_path = tokenJsonPath.trim()
    }

    try {
      const res = await submitScan({
        domain: domain.trim(),
        authorized: true,
        mode: scanMode,
        ...(auth ? { auth } : {}),
      })
      // Anonymous: only the mode (enum), never the domain/target.
      trackEvent('scan_started', { scan_mode: scanMode })
      router.push(`/scan/${res.job_id}/status`)
    } catch (err) {
      setLoading(false)
      // FULL scan on an unverified target: open target authorization; the scan
      // is retried (and re-checked by the backend) after ownership is proven.
      const authReq = targetAuthorizationRequired(err)
      if (authReq) {
        setClearanceTarget(authReq.target)
        return
      }
      if (err instanceof ApiError) {
        // Defensive: backend returns 202 (not 409) for duplicates today, but
        // preserve the branch that redirects on a 409 carrying a job_id.
        if (err.status === 409) {
          const jid = (err.body as { job_id?: string; detail?: { job_id?: string } })
          const id = jid?.job_id || jid?.detail?.job_id
          if (id) {
            router.push(`/scan/${id}/status`)
            return
          }
        }
        if (err.status === 403) {
          setSubmitError(
            'Authorization confirmation required - check the box to confirm you are authorized.',
          )
        } else {
          setSubmitError(err.message || 'Submission failed. Please try again.')
        }
      } else {
        setSubmitError('Cannot reach scan server. Is the backend running?')
      }
    }
  }

  // Decor lives in the wrapper's side margins, outside the 640px form column,
  // and is gated to 2xl so it only appears where there is genuine empty space.
  return (
    <div className="relative w-full overflow-x-clip">
      {/* Survey and inspection instruments - the page's own subject. Side
          margins only, clear of the 640px form column. */}
      <Plate src="magnifier-blueprint" rotate={5} opacity={0.24} delay={0}
        className="right-[2%] top-[40%] hidden h-[440px] w-[440px] -translate-y-1/2 xl:block" />
      <Plate src="theodolite" rotate={-7} opacity={0.24} delay={3}
        className="left-[2%] top-[16%] hidden h-[360px] w-[360px] xl:block" />
      <Plate src="compass-dividers" rotate={6} opacity={0.22} delay={6}
        className="bottom-[8%] left-[5%] hidden h-[320px] w-[320px] xl:block" />
    <div className="mx-auto flex min-h-screen w-full max-w-[640px] flex-col justify-center px-6 py-20">
      <header className="mb-8 flex flex-col items-center text-center onus-fade-up">
        <TargetReticle locked={domainValid} />
        <p className="signage mb-2.5 mt-5 text-[10px] text-accent text-glow-cyan">
          Evidence-Based Assessment
        </p>
        <h1 className="signage text-[16px] font-semibold leading-[1.5] tracking-[0.09em] text-ink">
          Assess a target you are<br />authorized to test.
        </h1>
        <p className="mx-auto mt-3 max-w-[420px] text-[13.5px] leading-relaxed text-ink-dim">
          Eight modules run in parallel. Findings are scored deterministically and
          verified before anything is reported. Evidence decides.
        </p>
      </header>

      <Panel
        className="spotlight relative p-6 onus-fade-up"
        style={{
          animationDelay: '60ms',
          boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.05), 0 24px 60px -24px rgba(0,0,0,0.85)',
        }}
      >
        <form onSubmit={handleSubmit} noValidate>
          {/* Target domain */}
          <label htmlFor="domain" className="mb-2 block text-[12px] font-medium text-ink-dim">
            Target Domain
          </label>
          <div className="relative">
            <input
              id="domain"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.com"
              autoComplete="off"
              spellCheck={false}
              aria-invalid={domainTouched && !domainValid}
              aria-describedby="domain-hint"
              className={cn(
                'w-full rounded-md border bg-canvas px-3.5 py-3 pr-10 font-mono text-[14px] text-ink placeholder:text-ink-faint focus:outline-none focus:ring-1',
                domainTouched && !domainValid
                  ? 'border-crit/60 focus:ring-crit/50'
                  : 'border-line focus:border-accent/60 focus:ring-accent/40',
              )}
            />
            {domainTouched && (
              <span className="absolute right-3 top-1/2 -translate-y-1/2">
                {domainValid ? (
                  <Check className="h-4 w-4 text-[var(--color-cyan)]" strokeWidth={2} />
                ) : (
                  <X className="h-4 w-4 text-crit" strokeWidth={2} />
                )}
              </span>
            )}
          </div>
          <p id="domain-hint" className="mt-1.5 min-h-[16px] text-[11px] text-ink-faint">
            {domainTouched && !domainValid
              ? 'Enter a domain (example.com) or a public IPv4 address.'
              : 'Enter the exact host you are authorized to scan.'}
          </p>

          {/* Scan mode - hosted only. Rendered once we know which tier we are;
              self-hosted shows nothing here and submits mode='full'. */}
          {hosted === true && (
          <div className="mb-4 mt-1 grid grid-cols-2 gap-2.5">
            {([
              ['quick', 'Quick Assessment', 'Fast passive assessment, usually done in a few minutes. No target verification required.'],
              ['full', 'Full VAPT Scan', 'Complete active assessment. Typically ~30 minutes and may pause for a decision. Target authorization required.'],
            ] as const).map(([m, title, desc]) => (
              <button
                key={m}
                type="button"
                onClick={() => {
                  setScanMode(m)
                  trackEvent(m === 'quick' ? 'quick_scan_selected' : 'full_scan_selected')
                }}
                className={cn(
                  'rounded-md border px-3.5 py-3 text-left transition-colors',
                  scanMode === m
                    ? 'border-accent/60 bg-accent/[0.06]'
                    : 'border-line hover:border-line-strong',
                )}
              >
                <div className={cn('text-[12px] font-semibold', scanMode === m ? 'text-accent' : 'text-ink')}>
                  {title}
                </div>
                <div className="mt-1 text-[10.5px] leading-snug text-ink-faint">{desc}</div>
              </button>
            ))}
          </div>
          )}

          {/* Authorization - the one amber (legal/policy) affordance */}
          <label
            className={cn(
              'mt-4 flex cursor-pointer items-start gap-3 rounded-md border p-3.5 transition-colors',
              authorized
                ? 'border-authz/50 bg-authz/[0.07]'
                : 'border-line bg-canvas hover:border-line-strong',
            )}
          >
            <span
              className={cn(
                'mt-[1px] flex h-[18px] w-[18px] shrink-0 items-center justify-center rounded-xs border',
                authorized ? 'border-authz bg-authz/20' : 'border-line-strong',
              )}
            >
              {authorized && <Check className="h-3 w-3 text-authz" strokeWidth={3} />}
            </span>
            <input
              type="checkbox"
              className="sr-only"
              checked={authorized}
              onChange={(e) => setAuthorized(e.target.checked)}
              aria-label="I confirm I am authorized to perform security testing on this domain"
            />
            <span className="text-[12.5px] leading-relaxed text-ink-dim">
              I confirm I am authorized to perform security testing on this domain.
            </span>
          </label>

          {/* Authenticated scan (optional) */}
          <div className="mt-4 overflow-hidden rounded-md border border-line bg-canvas">
            <button
              type="button"
              onClick={() => setAuthOpen((v) => !v)}
              className="flex w-full items-center justify-between px-3.5 py-3 text-left"
              aria-expanded={authOpen}
            >
              <span className="flex items-center gap-2 text-[12.5px] font-medium text-ink-dim">
                <KeyRound className="h-4 w-4 text-ink-faint" strokeWidth={1.6} />
                Authenticated scan
                <span className="text-ink-faint">(optional)</span>
              </span>
              <ChevronDown
                className={cn('h-4 w-4 text-ink-faint transition-transform', authOpen && 'rotate-180')}
                strokeWidth={1.6}
              />
            </button>

            {authOpen && (
              <div className="space-y-3 border-t border-line px-3.5 py-4">
                {/* Segmented control */}
                <div className="flex rounded-md border border-line bg-panel p-0.5">
                  {(['auto', 'form', 'json'] as LoginType[]).map((t) => (
                    <button
                      key={t}
                      type="button"
                      onClick={() => setLoginType(t)}
                      className={cn(
                        'flex-1 rounded-[5px] px-2 py-1.5 text-[12px] font-medium capitalize transition-colors',
                        loginType === t
                          ? 'bg-accent/15 text-accent'
                          : 'text-ink-dim hover:text-ink',
                      )}
                    >
                      {t === 'auto' ? 'Auto-detect' : t === 'json' ? 'JSON API' : 'Form'}
                    </button>
                  ))}
                </div>

                <Field label="Login URL" value={loginUrl} onChange={setLoginUrl} placeholder="https://example.com/login" mono />
                <div className="grid grid-cols-2 gap-3">
                  <Field label="Username" value={username} onChange={setUsername} placeholder="user" />
                  <Field label="Password" value={password} onChange={setPassword} placeholder="••••••••" type="password" />
                </div>

                {/* Advanced overrides */}
                <button
                  type="button"
                  onClick={() => setAdvancedOpen((v) => !v)}
                  className="flex items-center gap-1.5 text-[11px] font-medium text-ink-faint hover:text-ink-dim"
                >
                  <ChevronDown className={cn('h-3.5 w-3.5 transition-transform', advancedOpen && 'rotate-180')} strokeWidth={1.6} />
                  Advanced - field-name overrides
                </button>
                {advancedOpen && (
                  <div className="grid grid-cols-2 gap-3">
                    <Field label="Username field" value={usernameField} onChange={setUsernameField} placeholder="username" mono />
                    <Field label="Password field" value={passwordField} onChange={setPasswordField} placeholder="password" mono />
                  </div>
                )}

                {loginType === 'json' && (
                  <Field
                    label="Token JSON path"
                    value={tokenJsonPath}
                    onChange={setTokenJsonPath}
                    placeholder="data.token"
                    mono
                  />
                )}

                {authComplete && (
                  <div className="flex items-center gap-2 rounded-md border border-accent/30 bg-accent/[0.07] px-3 py-2 text-[11.5px] text-accent-soft">
                    <Lock className="h-3.5 w-3.5" strokeWidth={1.6} />
                    Will authenticate to target before scanning.
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Inline submit error - one at a time, above the button */}
          {submitError && (
            <div className="mt-4 flex items-start gap-2 rounded-md border border-crit/40 bg-crit/[0.08] px-3.5 py-3 text-[12.5px] text-crit">
              <CircleAlert className="mt-[1px] h-4 w-4 shrink-0" strokeWidth={1.7} />
              <span>{submitError}</span>
            </div>
          )}

          <MagneticButton
            type="submit"
            disabled={!canSubmit}
            className={cn(
              'signage mt-5 flex w-full items-center justify-center gap-2 rounded-[3px] px-4 py-3.5 text-[12px] font-bold',
              canSubmit
                ? 'bg-accent text-[#03141a] glow-cyan hover:bg-accent-soft'
                : 'cursor-not-allowed border border-line bg-raised-2 text-ink-faint',
            )}
          >
            {loading ? (
              <>
                <Spinner className="h-4 w-4" />
                Initiating scan…
              </>
            ) : (
              <>
                <ShieldCheck className="h-4 w-4" strokeWidth={1.8} />
                Begin Assessment
              </>
            )}
          </MagneticButton>

          {/* Hosted-tier fine print (limits / support the repo). Self-hosted
              users already run it locally and have no scan limits, so gate it
              on the same require_auth flag the mode toggle uses. */}
          {hosted === true && <HostingNotice />}
        </form>
      </Panel>

      {/* Capability pills - live from the API, never hardcoded */}
      {modules.length > 0 && (
        <div className="mt-8 onus-fade-up" style={{ animationDelay: '120ms' }}>
          {/* Module coverage as a systems panel - a checklist of instruments the
              tool runs, structured on a hairline grid (technical-drawing motif),
              not a tag cloud. */}
          <div className="mb-2.5 flex items-center gap-3">
            <p className="text-[10.5px] uppercase tracking-[0.22em] text-ink-faint">Systems engaged</p>
            <span className="h-px flex-1 bg-line" />
            <span className="tnum font-mono text-[10.5px] text-ink-faint">{modules.length}</span>
          </div>
          <Panel className="overflow-hidden">
            <div className="grid grid-cols-2 gap-px bg-line sm:grid-cols-4">
              {modules.map((m) => (
                <div key={m.id} className="flex items-center gap-2.5 bg-panel px-3.5 py-3">
                  <ModuleIcon hint={m.icon_hint} className="h-4 w-4 shrink-0 text-ink-dim" />
                  <span className="text-[12px] text-ink-dim">{m.label}</span>
                </div>
              ))}
            </div>
          </Panel>

          <div className="mt-4 overflow-hidden rounded-md border border-line bg-panel">
            <button
              type="button"
              onClick={() => setChecksOpen((v) => !v)}
              className="flex w-full items-center justify-between px-4 py-3 text-left text-[12.5px] font-medium text-ink-dim"
              aria-expanded={checksOpen}
            >
              What does this scan check?
              <ChevronDown className={cn('h-4 w-4 text-ink-faint transition-transform', checksOpen && 'rotate-180')} strokeWidth={1.6} />
            </button>
            {checksOpen && (
              <ul className="divide-y divide-line border-t border-line">
                {modules.map((m) => (
                  <li key={m.id} className="flex gap-3 px-4 py-3">
                    <ModuleIcon hint={m.icon_hint} className="mt-0.5 h-4 w-4 shrink-0 text-accent/70" />
                    <div>
                      <p className="text-[12.5px] font-medium text-ink">{m.label}</p>
                      <p className="mt-0.5 text-[12px] leading-relaxed text-ink-dim">{m.description}</p>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}

      {clearanceTarget && (
        <TargetClearance
          target={clearanceTarget}
          onClose={() => setClearanceTarget(null)}
          onVerified={async () => {
            const t = clearanceTarget
            setClearanceTarget(null)
            if (!t) return
            setSubmitError(null)
            setLoading(true)
            try {
              // Backend re-checks ownership; the frontend belief isn't trusted.
              const res = await submitScan({ domain: t, authorized: true, mode: 'full' })
              // The scan actually starts here (the first attempt threw before
              // starting); a full scan always follows the clearance flow.
              trackEvent('scan_started', { scan_mode: 'full' })
              router.push(`/scan/${res.job_id}/status`)
            } catch (err) {
              setLoading(false)
              setSubmitError(err instanceof ApiError ? err.message : 'Scan failed to start.')
            }
          }}
        />
      )}
    </div>
    </div>
  )
}

// The hero's instrument anchor: a reticle that idly breathes, then "locks on"
// (brackets tighten, crosshair + ring warm to the accent) the moment a valid
// target is entered - the front-panel gesture of an instrument acquiring a
// target, replacing a purely typographic hero.
function TargetReticle({ locked }: { locked: boolean }) {
  const stroke = locked ? 'var(--color-accent)' : 'var(--color-ink-faint)'
  const brackets: Array<[string, string, string]> = [
    ['left-0 top-0', 'border-l border-t', 'translate(7px,7px)'],
    ['right-0 top-0', 'border-r border-t', 'translate(-7px,7px)'],
    ['bottom-0 left-0', 'border-b border-l', 'translate(7px,-7px)'],
    ['bottom-0 right-0', 'border-b border-r', 'translate(-7px,-7px)'],
  ]
  return (
    <div className="relative h-[76px] w-[76px]" aria-hidden="true">
      <svg viewBox="0 0 76 76" className="onus-breathe h-full w-full">
        <circle
          cx="38"
          cy="38"
          r="25"
          fill="none"
          stroke={stroke}
          strokeWidth="1"
          opacity={locked ? 0.6 : 0.32}
          style={{ transition: 'stroke 0.5s, opacity 0.5s' }}
        />
        {[0, 90, 180, 270].map((a) => {
          const r = (a * Math.PI) / 180
          return (
            <line
              key={a}
              x1={38 + 22 * Math.cos(r)}
              y1={38 + 22 * Math.sin(r)}
              x2={38 + 26 * Math.cos(r)}
              y2={38 + 26 * Math.sin(r)}
              stroke={stroke}
              strokeWidth="1"
              strokeLinecap="round"
              style={{ transition: 'stroke 0.5s' }}
            />
          )
        })}
        <line x1="38" y1="30" x2="38" y2="46" stroke={stroke} strokeWidth="1" opacity="0.4" style={{ transition: 'stroke 0.5s' }} />
        <line x1="30" y1="38" x2="46" y2="38" stroke={stroke} strokeWidth="1" opacity="0.4" style={{ transition: 'stroke 0.5s' }} />
        <circle
          cx="38"
          cy="38"
          r={locked ? 3 : 1.6}
          fill={locked ? 'var(--color-accent)' : 'var(--color-ink-faint)'}
          style={{ transition: 'r 0.5s, fill 0.5s' }}
        />
      </svg>
      {brackets.map(([pos, brd, tl], i) => (
        <span
          key={i}
          className={cn('absolute h-2.5 w-2.5 transition-all duration-500', pos, brd)}
          style={{
            borderColor: locked ? 'var(--color-accent)' : 'var(--color-line-strong)',
            transform: locked ? tl : 'translate(0,0)',
          }}
        />
      ))}
    </div>
  )
}

function Field({
  label,
  value,
  onChange,
  placeholder,
  type = 'text',
  mono,
}: {
  label: string
  value: string
  onChange: (v: string) => void
  placeholder?: string
  type?: string
  mono?: boolean
}) {
  const id = useMemo(() => 'f-' + label.toLowerCase().replace(/\s+/g, '-'), [label])
  return (
    <div>
      <label htmlFor={id} className="mb-1.5 block text-[11.5px] font-medium text-ink-dim">
        {label}
      </label>
      <input
        id={id}
        type={type}
        value={value}
        autoComplete="off"
        spellCheck={false}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className={cn(
          'w-full rounded-md border border-line bg-panel px-3 py-2 text-[13px] text-ink placeholder:text-ink-faint focus:border-accent/60 focus:outline-none focus:ring-1 focus:ring-accent/40',
          mono && 'font-mono',
        )}
      />
    </div>
  )
}
