'use client'

/**
 * Shared primitives for the hosted auth experience — glass card, inputs,
 * segmented password meter, magnetic CTA, six-box OTP, and the scramble /
 * resolver text animations. Pure CSS transitions + Web Animations (no motion
 * library). Colors follow the auth surface palette: #00F0FF cyan, #FF0055
 * crimson, dark-glass card.
 */
import Link from 'next/link'
import {
  ButtonHTMLAttributes,
  InputHTMLAttributes,
  ReactNode,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from 'react'
import { Eye, EyeOff, Check, Copy } from 'lucide-react'

const CYAN = '#00F0FF'
const CRIMSON = '#FF0055'

export function AuthCard({ children }: { children: ReactNode }) {
  return (
    <div
      className="relative overflow-hidden rounded-[10px] px-7 py-8 backdrop-blur-xl"
      style={{
        background: 'rgba(3, 3, 7, 0.6)',
        border: '1px solid rgba(255, 255, 255, 0.04)',
        boxShadow: '0 20px 60px -20px rgba(0,0,0,0.8)',
      }}
    >
      <AutoHeight>{children}</AutoHeight>
    </div>
  )
}

/** Smoothly animates its own height as children change (step transitions). */
export function AutoHeight({ children }: { children: ReactNode }) {
  const inner = useRef<HTMLDivElement>(null)
  const [h, setH] = useState<number | 'auto'>('auto')

  useLayoutEffect(() => {
    const el = inner.current
    if (!el) return
    const ro = new ResizeObserver(() => setH(el.offsetHeight))
    ro.observe(el)
    setH(el.offsetHeight)
    return () => ro.disconnect()
  }, [])

  return (
    <div
      style={{ height: h === 'auto' ? 'auto' : h, transition: 'height 320ms cubic-bezier(0.16,1,0.3,1)' }}
    >
      <div ref={inner}>{children}</div>
    </div>
  )
}

/** Step content: fades + slides in when `stepKey` changes. */
export function StepTransition({ stepKey, children }: { stepKey: string; children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    el.animate(
      [
        { opacity: 0, transform: 'translateY(8px)' },
        { opacity: 1, transform: 'translateY(0)' },
      ],
      { duration: 340, easing: 'cubic-bezier(0.16,1,0.3,1)' },
    )
  }, [stepKey])
  return <div ref={ref}>{children}</div>
}

// ── Headings ─────────────────────────────────────────────────────────────────
export function CardHeader({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <div className="mb-6">
      <h1 className="font-display text-[15px] font-600 uppercase tracking-[0.18em] text-white">
        {title}
      </h1>
      {subtitle && <p className="mt-2 text-[13px] leading-relaxed text-white/45">{subtitle}</p>}
    </div>
  )
}

// ── Inputs ───────────────────────────────────────────────────────────────────
interface FieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string
}

export function Field({ label, id, ...props }: FieldProps) {
  return (
    <label htmlFor={id} className="mb-4 block">
      <span className="mb-1.5 block font-mono text-[11px] uppercase tracking-wider text-white/40">
        {label}
      </span>
      <input
        id={id}
        className="onus-auth-input w-full rounded-[5px] px-3 py-2.5 text-[14px] text-white outline-none transition-colors placeholder:text-white/25"
        {...props}
      />
    </label>
  )
}

export function PasswordField({
  label,
  id,
  value,
  onChange,
  meter,
  ...props
}: FieldProps & { meter?: boolean }) {
  const [show, setShow] = useState(false)
  return (
    <label htmlFor={id} className="mb-4 block">
      <span className="mb-1.5 block font-mono text-[11px] uppercase tracking-wider text-white/40">
        {label}
      </span>
      <div className="relative">
        <input
          id={id}
          type={show ? 'text' : 'password'}
          value={value}
          onChange={onChange}
          className="onus-auth-input w-full rounded-[5px] px-3 py-2.5 pr-10 text-[14px] text-white outline-none transition-colors placeholder:text-white/25"
          {...props}
        />
        <button
          type="button"
          onClick={() => setShow((s) => !s)}
          aria-label={show ? 'Hide password' : 'Show password'}
          className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-white/35 transition-colors hover:text-white/70"
        >
          {show ? <EyeOff size={16} /> : <Eye size={16} />}
        </button>
      </div>
      {meter && <SegmentedMeter value={String(value ?? '')} />}
    </label>
  )
}

/** Five-segment cyan security meter — visual feedback only (server enforces). */
export function SegmentedMeter({ value }: { value: string }) {
  const score = passwordScore(value)
  return (
    <div className="mt-2 flex gap-1.5" aria-hidden="true">
      {[0, 1, 2, 3, 4].map((i) => (
        <span
          key={i}
          className="h-1 flex-1 rounded-full transition-colors duration-200"
          style={{ background: i < score ? CYAN : 'rgba(255,255,255,0.08)' }}
        />
      ))}
    </div>
  )
}

export function passwordScore(pw: string): number {
  let s = 0
  if (pw.length >= 10) s++
  if (pw.length >= 14) s++
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++
  if (/\d/.test(pw)) s++
  if (/[^A-Za-z0-9]/.test(pw)) s++
  return Math.min(5, s)
}

// ── Error / notice ───────────────────────────────────────────────────────────
export function ErrorText({ children }: { children: ReactNode }) {
  if (!children) return null
  return (
    <p
      role="alert"
      className="mb-4 rounded-[5px] px-3 py-2 font-mono text-[12px] leading-snug"
      style={{ background: 'rgba(255,0,85,0.08)', border: `1px solid rgba(255,0,85,0.2)`, color: CRIMSON }}
    >
      {children}
    </p>
  )
}

// ── Magnetic CTA ─────────────────────────────────────────────────────────────
export function CtaButton({
  children,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement>) {
  const ref = useRef<HTMLButtonElement>(null)
  const onMove = (e: React.PointerEvent) => {
    const el = ref.current
    if (!el) return
    const b = el.getBoundingClientRect()
    const dx = (e.clientX - (b.left + b.width / 2)) / b.width
    const dy = (e.clientY - (b.top + b.height / 2)) / b.height
    el.style.transform = `translate(${dx * 4}px, ${dy * 4}px)`
  }
  const reset = () => {
    if (ref.current) ref.current.style.transform = 'translate(0,0)'
  }
  return (
    <button
      ref={ref}
      onPointerMove={onMove}
      onPointerLeave={reset}
      className="onus-auth-cta mt-2 w-full rounded-[5px] py-2.5 font-display text-[13px] font-600 uppercase tracking-[0.14em] transition-transform duration-150 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-40"
      {...props}
    >
      {children}
    </button>
  )
}

export function LinkRow({ children }: { children: ReactNode }) {
  return <p className="mt-5 text-center font-mono text-[12px] text-white/40">{children}</p>
}

export function TextLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <Link href={href} className="text-[color:var(--cyan)] hover:underline" style={{ ['--cyan' as string]: CYAN }}>
      {children}
    </Link>
  )
}

// ── Six-box OTP input ────────────────────────────────────────────────────────
export function OtpInput({
  length = 6,
  onComplete,
  disabled,
}: {
  length?: number
  onComplete: (code: string) => void
  disabled?: boolean
}) {
  const [digits, setDigits] = useState<string[]>(Array(length).fill(''))
  const refs = useRef<(HTMLInputElement | null)[]>([])

  const emit = (arr: string[]) => {
    if (arr.every((d) => d !== '')) onComplete(arr.join(''))
  }

  const setAt = (i: number, v: string) => {
    setDigits((prev) => {
      const next = [...prev]
      next[i] = v
      return next
    })
  }

  const onChange = (i: number, raw: string) => {
    const v = raw.replace(/\D/g, '')
    if (!v) {
      setAt(i, '')
      return
    }
    const chars = v.split('')
    setDigits((prev) => {
      const next = [...prev]
      let idx = i
      for (const c of chars) {
        if (idx >= length) break
        next[idx] = c
        idx++
      }
      const focus = Math.min(idx, length - 1)
      refs.current[focus]?.focus()
      emit(next)
      return next
    })
  }

  const onKeyDown = (i: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !digits[i] && i > 0) {
      refs.current[i - 1]?.focus()
    }
  }

  const onPaste = (e: React.ClipboardEvent) => {
    const text = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, length)
    if (!text) return
    e.preventDefault()
    const next = Array(length).fill('')
    text.split('').forEach((c, idx) => (next[idx] = c))
    setDigits(next)
    refs.current[Math.min(text.length, length - 1)]?.focus()
    emit(next)
  }

  return (
    <div className="mb-4 flex justify-between gap-2" onPaste={onPaste}>
      {digits.map((d, i) => (
        <input
          key={i}
          ref={(el) => {
            refs.current[i] = el
          }}
          value={d}
          disabled={disabled}
          inputMode="numeric"
          autoComplete={i === 0 ? 'one-time-code' : 'off'}
          maxLength={1}
          aria-label={`Digit ${i + 1}`}
          onChange={(e) => onChange(i, e.target.value)}
          onKeyDown={(e) => onKeyDown(i, e)}
          className="onus-auth-input h-12 w-full rounded-[5px] text-center font-mono text-[18px] text-white outline-none transition-colors disabled:opacity-50"
        />
      ))}
    </div>
  )
}

// ── Scramble text (loading label) ────────────────────────────────────────────
const GLYPHS = '!<>-_\\/[]{}=+*^?#0123456789ABCDEF'

export function ScrambleText({ text, active }: { text: string; active: boolean }) {
  const [display, setDisplay] = useState(text)
  useEffect(() => {
    if (!active) {
      setDisplay(text)
      return
    }
    let frame = 0
    const id = window.setInterval(() => {
      frame++
      setDisplay(
        text
          .split('')
          .map((ch, i) => (ch === ' ' ? ' ' : i < frame / 2 ? ch : GLYPHS[Math.floor(Math.random() * GLYPHS.length)]))
          .join(''),
      )
      if (frame / 2 >= text.length) window.clearInterval(id)
    }, 45)
    return () => window.clearInterval(id)
  }, [active, text])
  return <span className="font-mono text-[13px] tracking-wide" style={{ color: CYAN }}>{display}</span>
}

// ── Resolver terminal log (domain verification) ──────────────────────────────
export function ResolverLog({ lines, active }: { lines: string[]; active: boolean }) {
  const [shown, setShown] = useState(0)
  useEffect(() => {
    if (!active) {
      setShown(0)
      return
    }
    let n = 0
    const id = window.setInterval(() => {
      n++
      setShown(n)
      if (n >= lines.length) window.clearInterval(id)
    }, 420)
    return () => window.clearInterval(id)
  }, [active, lines.length])
  if (!active) return null
  return (
    <div
      className="mb-4 rounded-[5px] p-3 font-mono text-[11px] leading-relaxed"
      style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(255,255,255,0.05)' }}
    >
      {lines.slice(0, shown).map((l, i) => (
        <div key={i} style={{ color: i === shown - 1 ? CYAN : 'rgba(255,255,255,0.4)' }}>
          {l}
          {i === shown - 1 && shown < lines.length && <span className="onus-caret">▋</span>}
        </div>
      ))}
    </div>
  )
}

// ── Copy button ──────────────────────────────────────────────────────────────
export function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    } catch {
      /* clipboard unavailable — no-op */
    }
  }
  return (
    <button
      type="button"
      onClick={copy}
      aria-label="Copy"
      className="shrink-0 rounded-[4px] p-1.5 text-white/40 transition-colors hover:text-white/80"
      style={copied ? { color: CYAN } : undefined}
    >
      {copied ? <Check size={14} /> : <Copy size={14} />}
    </button>
  )
}
