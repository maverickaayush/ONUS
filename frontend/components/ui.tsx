'use client'

import { cloneElement, useEffect, useId, useRef, useState, type ReactElement } from 'react'
import type { ScanStatus, Severity } from '@/lib/api'
import { SEVERITY, cn } from '@/lib/format'

// ════════════════════════════════════════════════════════════════════════════
// DIRECTION B - signature interaction primitives
// ════════════════════════════════════════════════════════════════════════════

// ── ScrambleText ── cryptographic decode reveal. Fires ONCE, on first mount
// (first appearance of a genuinely new value). The effect keys on the target
// string, so a routine poll returning the same value does NOT re-scramble -
// only a real change re-decodes. aria-label carries the true value for SR.
export function ScrambleText({
  value,
  className,
  duration = 340,
}: {
  value: string | number
  className?: string
  duration?: number
}) {
  const target = String(value)
  const reduced = usePrefersReducedMotion()
  const [display, setDisplay] = useState(target)
  const rafRef = useRef<number | null>(null)
  useEffect(() => {
    if (reduced) {
      setDisplay(target)
      return
    }
    const chars = '!<>-_\\/[]{}=+*^?#01ABCDEF§±'
    const start = performance.now()
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration)
      const revealed = Math.floor(t * target.length)
      let out = ''
      for (let i = 0; i < target.length; i++) {
        out += i < revealed || target[i] === ' ' ? target[i] : chars[Math.floor(Math.random() * chars.length)]
      }
      setDisplay(out)
      if (t < 1) rafRef.current = requestAnimationFrame(tick)
      else setDisplay(target)
    }
    rafRef.current = requestAnimationFrame(tick)
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current)
    }
  }, [target, reduced, duration])
  return (
    <span className={className} aria-label={target}>
      {display}
    </span>
  )
}

// ── MagneticButton ── pulls a few px toward the cursor as it approaches; glow
// intensifies on hover (CSS). Snaps still under reduced-motion.
export function MagneticButton({
  children,
  className,
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  const ref = useRef<HTMLButtonElement>(null)
  const reduced = usePrefersReducedMotion()
  return (
    <button
      ref={ref}
      onMouseMove={(e) => {
        if (reduced || !ref.current) return
        const r = ref.current.getBoundingClientRect()
        const mx = (e.clientX - (r.left + r.width / 2)) * 0.18
        const my = (e.clientY - (r.top + r.height / 2)) * 0.3
        ref.current.style.transform = `translate(${mx.toFixed(1)}px, ${my.toFixed(1)}px)`
      }}
      onMouseLeave={() => {
        if (ref.current) ref.current.style.transform = ''
      }}
      className={cn('transition-transform duration-200', className)}
      {...props}
    >
      {children}
    </button>
  )
}

// ── SpotlightCard ── radial cyan glow tracks the cursor across the surface.
export function SpotlightCard({
  children,
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  const ref = useRef<HTMLDivElement>(null)
  return (
    <div
      ref={ref}
      onMouseMove={(e) => {
        if (!ref.current) return
        const r = ref.current.getBoundingClientRect()
        ref.current.style.setProperty('--mx', ((e.clientX - r.left) / r.width).toFixed(3))
        ref.current.style.setProperty('--my', ((e.clientY - r.top) / r.height).toFixed(3))
      }}
      className={cn('spotlight', className)}
      {...props}
    >
      {children}
    </div>
  )
}

// ── Logo ── the official ONUS triangle mark, rendered on transparent in
// currentColor. The source SVG ships with a white export background + dark
// path; we use only the mark path, unmodified in geometry.
export function OnusMark({ className, style }: { className?: string; style?: React.CSSProperties }) {
  return (
    <svg
      viewBox="0 0 2048 2048"
      className={className}
      style={style}
      fill="currentColor"
      aria-hidden="true"
    >
      <path d="M1024.19 534.779C1027.44 537.995 1052.55 579.131 1056.86 586.04L1120.56 687.811C1131.46 705.218 1142.64 724.096 1154 741.071C1144.69 754.716 1134.55 772.332 1125.54 786.594L1066.29 879.34L838.468 1232.27C880.889 1234.04 930.329 1232.94 973.259 1232.94L1207.1 1232.83C1195.99 1212.53 1180.51 1188.5 1168.29 1168.5C1141.09 1124.38 1114.15 1080.09 1087.47 1035.65C1114.21 994.428 1141.16 953.347 1168.34 912.41C1181.26 892.791 1200.66 861.401 1214.63 843.324C1226.63 860.305 1240.53 883.882 1251.93 901.953L1322.33 1013.81L1555.45 1385.53C1581.89 1427.97 1610.14 1471.72 1635.52 1514.57L845.334 1514.4L568.17 1514.39C516.879 1514.38 463.685 1513.65 412.523 1514.59C426.901 1492.28 440.861 1468.82 455.043 1446.26L584.897 1238.81L842.521 826.618L962.796 633.284C982.236 602.039 1003.83 564.773 1024.19 534.779Z" />
    </svg>
  )
}

export function OnusWordmark({ className }: { className?: string }) {
  return (
    <span className={cn('flex items-center gap-2.5', className)}>
      <OnusMark className="h-6 w-6 text-accent text-glow-cyan" />
      <span className="signage text-[15px] font-bold text-ink text-glow-cyan">ONUS</span>
    </span>
  )
}

// ── Tooltip ── hand-rolled to keep this design system dependency-free (every
// primitive here is bespoke). Accessible where a native `title` isn't: the
// trigger is focusable, the tip is wired via aria-describedby and announced on
// keyboard focus, and Escape dismisses it. Renders its single child element as
// the trigger (cloneElement) so a truncated heading stays the trigger unchanged.
export function Tooltip({
  label,
  children,
  align = 'left',
}: {
  label: string
  children: ReactElement<Record<string, unknown>>
  align?: 'left' | 'right'
}) {
  const [open, setOpen] = useState(false)
  const id = useId()
  const childProps = children.props
  const trigger = cloneElement(children, {
    tabIndex: 0,
    'aria-describedby': open ? id : undefined,
    onMouseEnter: () => setOpen(true),
    onMouseLeave: () => setOpen(false),
    onFocus: () => setOpen(true),
    onBlur: () => setOpen(false),
    onKeyDown: (e: React.KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
      ;(childProps.onKeyDown as ((e: React.KeyboardEvent) => void) | undefined)?.(e)
    },
  })
  return (
    <span className="relative block min-w-0">
      {trigger}
      {open && (
        <span
          role="tooltip"
          id={id}
          className={cn(
            'glass absolute top-full z-50 mt-1.5 max-w-[min(90vw,460px)] break-all rounded-[3px] px-2.5 py-1.5 font-mono text-[11.5px] leading-relaxed text-ink',
            align === 'right' ? 'right-0' : 'left-0',
          )}
        >
          {label}
        </span>
      )}
    </span>
  )
}

// ── InfoPopover ── click-toggled, outside-click + Escape to close, focus
// returns to the trigger on close. Used to surface secondary evidence (the CVSS
// vector) on demand without a permanent column.
export function InfoPopover({
  trigger,
  children,
  label,
}: {
  trigger: React.ReactNode
  children: React.ReactNode
  label: string
}) {
  const [open, setOpen] = useState(false)
  const wrapRef = useRef<HTMLSpanElement>(null)
  const btnRef = useRef<HTMLButtonElement>(null)
  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setOpen(false)
        btnRef.current?.focus()
      }
    }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])
  return (
    <span ref={wrapRef} className="relative inline-flex">
      <button
        ref={btnRef}
        type="button"
        aria-expanded={open}
        aria-label={label}
        onClick={(e) => {
          e.stopPropagation()
          setOpen((v) => !v)
        }}
        className="inline-flex items-center"
      >
        {trigger}
      </button>
      {open && (
        <span
          role="dialog"
          aria-label={label}
          className="glass absolute left-0 top-full z-50 mt-1.5 w-max max-w-[min(90vw,360px)] rounded-[3px] px-3 py-2"
          onClick={(e) => e.stopPropagation()}
        >
          {children}
        </span>
      )}
    </span>
  )
}

// ── reduced motion ──
export function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState(false)
  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    setReduced(mq.matches)
    const on = () => setReduced(mq.matches)
    mq.addEventListener('change', on)
    return () => mq.removeEventListener('change', on)
  }, [])
  return reduced
}

// ── count-up ──
export function useCountUp(target: number, duration = 900): number {
  const [value, setValue] = useState(0)
  const reduced = usePrefersReducedMotion()
  const rafRef = useRef<number | null>(null)
  useEffect(() => {
    if (reduced) {
      setValue(target)
      return
    }
    const start = performance.now()
    const from = 0
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration)
      const eased = 1 - Math.pow(1 - t, 3)
      setValue(from + (target - from) * eased)
      if (t < 1) rafRef.current = requestAnimationFrame(tick)
    }
    rafRef.current = requestAnimationFrame(tick)
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current)
    }
  }, [target, duration, reduced])
  return value
}

// ── module icons ── bespoke line-glyphs, one per module, drawn in the same
// geometry/stroke as the rest of the system but each with enough character to be
// identified out of context. Keyed by the API's icon_hint; generic fallback for
// an unknown hint (a 9th module ships without a frontend change). This is the
// most-repeated visual element in the product, so it earns custom linework.
const MODULE_GLYPHS: Record<string, React.ReactNode> = {
  // recon - hub & spokes: discovery radiating from a target
  network: (
    <>
      <circle cx="12" cy="12" r="2.4" />
      <circle cx="5" cy="6" r="1.7" />
      <circle cx="19" cy="7" r="1.7" />
      <circle cx="12" cy="20" r="1.7" />
      <line x1="10.3" y1="10.6" x2="6.3" y2="7.2" />
      <line x1="13.8" y1="10.8" x2="17.6" y2="8.1" />
      <line x1="12" y1="14.4" x2="12" y2="18.3" />
    </>
  ),
  // webscan - globe (equator + meridian)
  web: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <line x1="3.5" y1="12" x2="20.5" y2="12" />
      <path d="M12 3.5 C 7.6 6.5 7.6 17.5 12 20.5 C 16.4 17.5 16.4 6.5 12 3.5 Z" />
    </>
  ),
  // ssl_tls - padlock with a verified check
  lock: (
    <>
      <path d="M8 10 V7.5 a4 4 0 0 1 8 0 V10" />
      <rect x="5.5" y="10" width="13" height="9.5" rx="2.2" />
      <path d="M9.6 14.7 l1.8 1.8 L15 12.8" />
    </>
  ),
  // headers - response header fields, varied lengths
  list: (
    <>
      <rect x="5" y="3" width="14" height="18" rx="2.2" />
      <line x1="8" y1="8" x2="16" y2="8" />
      <line x1="8" y1="11.5" x2="14" y2="11.5" />
      <line x1="8" y1="15" x2="15.2" y2="15" />
      <line x1="8" y1="18" x2="12" y2="18" />
    </>
  ),
  // owasp - shield with an exclamation
  alert: (
    <>
      <path d="M12 3 L19 5.8 V11 c0 5 -3.4 7.8 -7 9.2 C 8.4 18.8 5 16 5 11 V5.8 Z" />
      <line x1="12" y1="8.6" x2="12" y2="12.9" />
      <path d="M12 15.6 h0.01" />
    </>
  ),
  // tech_fingerprint - concentric ridges
  fingerprint: (
    <>
      <path d="M6.5 13 a5.5 5.5 0 0 1 11 0" />
      <path d="M8.6 13.4 a3.4 3.4 0 0 1 6.8 0" />
      <path d="M10.6 13.8 a1.5 1.5 0 0 1 2.9 0" />
      <path d="M12 8 h0.01" />
    </>
  ),
  // nuclei - reticle / target
  target: (
    <>
      <circle cx="12" cy="12" r="8" />
      <circle cx="12" cy="12" r="3.6" />
      <path d="M12 12 h0.01" />
      <line x1="12" y1="2.6" x2="12" y2="5" />
      <line x1="12" y1="19" x2="12" y2="21.4" />
      <line x1="2.6" y1="12" x2="5" y2="12" />
      <line x1="19" y1="12" x2="21.4" y2="12" />
    </>
  ),
  // enumeration - folder being searched
  folder: (
    <>
      <path d="M4 8 a2 2 0 0 1 2 -2 h3.2 l1.8 2 h7 a2 2 0 0 1 2 2 v7 a2 2 0 0 1 -2 2 H6 a2 2 0 0 1 -2 -2 Z" />
      <circle cx="12.4" cy="13.4" r="2.2" />
      <line x1="14.1" y1="15.1" x2="16" y2="17" />
    </>
  ),
  _fallback: (
    <>
      <rect x="4" y="4" width="16" height="16" rx="3.5" />
      <path d="M12 12 h0.01" />
    </>
  ),
}
export function ModuleIcon({
  hint,
  className,
}: {
  hint: string
  className?: string
}) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.6}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      {MODULE_GLYPHS[hint] ?? MODULE_GLYPHS._fallback}
    </svg>
  )
}

// ── MarkNotFound ── absence-state glyph in the emblem's line language: an empty
// triangle (nothing to prove here) rather than a stock magnifier.
export function MarkNotFound({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.4}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      <path d="M12 4 L20 19 L4 19 Z" opacity="0.55" />
      <line x1="9" y1="14.5" x2="15" y2="14.5" />
    </svg>
  )
}

// ── Panel ──
export function Panel({
  children,
  className,
  raised,
  ...rest
}: React.HTMLAttributes<HTMLDivElement> & { raised?: boolean }) {
  return (
    <div
      className={cn(
        'panel-frame rounded-[3px] border border-line',
        raised ? 'bg-raised' : 'bg-panel',
        className,
      )}
      {...rest}
    >
      {children}
    </div>
  )
}

// ── SchematicCorners ── faint technical-drawing reticle brackets framing an
// "instrument" panel (risk gauge, ops timeline). Engineering-schematic, not HUD:
// hairline, no glow, no color, no motion. Purely decorative overlay.
export function SchematicCorners() {
  const arm = 'absolute h-2.5 w-2.5 border-line-strong'
  return (
    <div aria-hidden className="pointer-events-none absolute inset-1.5">
      <span className={cn(arm, 'left-0 top-0 border-l border-t')} />
      <span className={cn(arm, 'right-0 top-0 border-r border-t')} />
      <span className={cn(arm, 'bottom-0 left-0 border-b border-l')} />
      <span className={cn(arm, 'bottom-0 right-0 border-b border-r')} />
    </div>
  )
}

// ── SeverityBadge ──
export function SeverityBadge({
  severity,
  size = 'sm',
}: {
  severity: Severity
  size?: 'xs' | 'sm'
}) {
  const meta = SEVERITY[severity]
  const isCrit = severity === 'Critical'
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-xs border font-medium tabular-nums',
        'font-mono uppercase tracking-wider',
        size === 'xs' ? 'px-1.5 py-0.5 text-[10px]' : 'px-2 py-[3px] text-[11px]',
        isCrit && 'onus-critical-pulse text-glow-crimson',
      )}
      style={{
        color: meta.varName,
        borderColor: 'color-mix(in srgb, ' + meta.varName + (isCrit ? ' 90%' : ' 55%') + ', transparent)',
        backgroundColor: 'color-mix(in srgb, ' + 'currentColor 12%, transparent)',
      }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: meta.varName }} />
      {meta.label}
    </span>
  )
}

// ── ConfidenceTag ── quiet marker beside severity. No tag for `probable`.
export function ConfidenceTag({ confidence }: { confidence?: string }) {
  if (confidence === 'confirmed') {
    // The settle (same gesture as a module completing) is deliberate: across the
    // whole product, a value scaling into place means "this is confirmed." It's
    // the quiet, most direct expression of evidence-over-probability.
    return (
      <span className="inline-flex origin-left items-center gap-1 rounded-xs px-1.5 py-0.5 text-[10px] font-medium text-[var(--color-cyan)] onus-scale-in">
        <span className="h-1 w-1 rounded-full bg-[var(--color-cyan)]" />
        Verified
      </span>
    )
  }
  if (confidence === 'unverified') {
    return (
      <span className="inline-flex items-center gap-1 rounded-xs px-1.5 py-0.5 text-[10px] font-medium text-crit">
        <span className="h-1 w-1 rounded-full bg-crit" />
        Requires Manual Review
      </span>
    )
  }
  // `probable` (or absent) intentionally renders nothing.
  return null
}

// ── StatusPill (7 scan states + 4 module states) ──
const STATUS_META: Record<string, { label: string; color: string; dim?: boolean }> = {
  queued: { label: 'Queued', color: 'var(--color-ink-dim)', dim: true },
  running: { label: 'Running', color: 'var(--color-accent)' },
  analysing: { label: 'Analysing', color: 'var(--color-accent-soft)' },
  awaiting_user_decision: { label: 'Awaiting Decision', color: 'var(--color-high)' },
  complete: { label: 'Complete', color: 'var(--color-cyan)' },
  failed: { label: 'Failed', color: 'var(--color-crit)' },
  cancelled: { label: 'Cancelled', color: 'var(--color-ink-faint)', dim: true },
}
export function StatusPill({
  status,
  size = 'sm',
}: {
  status: ScanStatus | string
  size?: 'xs' | 'sm'
}) {
  const meta = STATUS_META[status] ?? { label: status, color: 'var(--color-ink-dim)', dim: true }
  const live = status === 'running' || status === 'analysing'
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border font-medium',
        size === 'xs' ? 'px-2 py-0.5 text-[10px]' : 'px-2.5 py-1 text-[11px]',
      )}
      style={{
        color: meta.color,
        borderColor: 'color-mix(in srgb, ' + meta.color + ' 40%, transparent)',
        backgroundColor: 'color-mix(in srgb, ' + meta.color + ' 12%, transparent)',
      }}
    >
      <span className="relative flex h-1.5 w-1.5">
        {live && (
          <span
            className="absolute inline-flex h-full w-full rounded-full opacity-60"
            style={{ backgroundColor: meta.color, animation: 'onus-pulse-ring 2s ease-out infinite' }}
          />
        )}
        <span className="relative inline-flex h-1.5 w-1.5 rounded-full" style={{ backgroundColor: meta.color }} />
      </span>
      {meta.label}
    </span>
  )
}

// ── ProgressBar ──
export function ProgressBar({
  value,
  className,
  active = true,
}: {
  value: number
  className?: string
  active?: boolean
}) {
  const pct = Math.max(0, Math.min(100, value))
  return (
    <div className={cn('relative h-1.5 w-full overflow-hidden rounded-full bg-raised-2', className)}>
      <div
        className={cn('relative h-full rounded-full transition-[width] duration-700', active && pct < 100 && 'onus-shimmer')}
        style={{
          width: `${pct}%`,
          background:
            pct >= 100
              ? 'linear-gradient(90deg,var(--color-accent-deep),var(--color-cyan))'
              : 'linear-gradient(90deg,var(--color-accent-deep),var(--color-accent))',
        }}
      />
    </div>
  )
}

// ── Spinner ──
export function Spinner({ className }: { className?: string }) {
  return (
    <span
      className={cn('inline-block rounded-full border-2 border-current border-t-transparent onus-spin', className)}
      aria-hidden="true"
    />
  )
}

// ── RiskScoreRing ── circular gauge, banded, count-up animated.
export function RiskScoreRing({ score }: { score: number }) {
  const animated = useCountUp(score, 1100)
  const reduced = usePrefersReducedMotion()
  const shown = reduced ? score : Math.round(animated)
  const band =
    score >= 70
      ? { label: 'HIGH RISK', color: 'var(--color-crit)' }
      : score >= 40
        ? { label: 'MODERATE RISK', color: 'var(--color-high)' }
        : { label: 'LOW RISK', color: 'var(--color-cyan)' }
  const R = 74
  const C = 2 * Math.PI * R
  const frac = Math.max(0, Math.min(100, reduced ? score : animated)) / 100
  return (
    <div className="flex flex-col items-center">
      <div className={cn('relative h-[188px] w-[188px] rounded-full', score >= 70 && 'onus-critical-pulse')}>
        <svg viewBox="0 0 188 188" className="h-full w-full -rotate-90">
          <defs>
            {/* The arc gets its own gradient + soft glow rather than a flat
                stroke - the difference between "generic circular progress" and
                an instrument reading. Gradient runs deep→light along the fill. */}
            <linearGradient id="risk-arc" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0%" stopColor={`color-mix(in srgb, ${band.color} 68%, #000)`} />
              <stop offset="55%" stopColor={band.color} />
              <stop offset="100%" stopColor={`color-mix(in srgb, ${band.color} 62%, #fff)`} />
            </linearGradient>
            {/* Faint radial lift so the numeral doesn't sit on flat black */}
            <radialGradient id="risk-center" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="rgba(255,255,255,0.05)" />
              <stop offset="70%" stopColor="rgba(255,255,255,0.012)" />
              <stop offset="100%" stopColor="rgba(255,255,255,0)" />
            </radialGradient>
          </defs>
          {/* center lift + inner bezel line separating dial from face */}
          <circle cx="94" cy="94" r="58" fill="url(#risk-center)" />
          <circle cx="94" cy="94" r="63" fill="none" stroke="var(--color-line)" strokeWidth="1" />
          {/* calibration ticks at 0/25/50/75/100 (0 and 100 share top) */}
          {[0, 90, 180, 270].map((a) => {
            const r = (a * Math.PI) / 180
            return (
              <line
                key={a}
                x1={94 + 64 * Math.cos(r)}
                y1={94 + 64 * Math.sin(r)}
                x2={94 + 68 * Math.cos(r)}
                y2={94 + 68 * Math.sin(r)}
                stroke="var(--color-ink-faint)"
                strokeWidth="1.5"
                strokeLinecap="round"
              />
            )
          })}
          <circle cx="94" cy="94" r={R} fill="none" stroke="var(--color-raised-2)" strokeWidth="9" />
          <circle
            cx="94"
            cy="94"
            r={R}
            fill="none"
            stroke="url(#risk-arc)"
            strokeWidth="9"
            strokeLinecap="round"
            strokeDasharray={C}
            strokeDashoffset={C * (1 - frac)}
            style={{
              filter: `drop-shadow(0 0 5px color-mix(in srgb, ${band.color} 50%, transparent))`,
            }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <ScrambleText
            value={score}
            duration={560}
            className={cn('tnum font-mono text-[52px] font-bold leading-none text-ink', score >= 70 && 'text-glow-crimson')}
          />
          <span className="mt-1 font-mono text-[10px] tracking-[0.2em] text-ink-faint">/ 100</span>
        </div>
      </div>
      <span className="signage mt-3.5 text-[12px] font-bold" style={{ color: band.color }}>
        {band.label}
      </span>
    </div>
  )
}
