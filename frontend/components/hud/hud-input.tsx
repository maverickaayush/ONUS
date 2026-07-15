'use client'

/**
 * Kinetic hardware inputs.
 *  - KineticField: labelled input; on focus a cyan laser sweeps outward from the
 *    centre of the bottom border to both edges.
 *  - KineticPassword: each newly typed character briefly cycles through encrypted
 *    glyphs (~200ms) before resolving to a mask char, as if the hardware is
 *    encrypting the keystroke. Real value stays in state; only the render cycles.
 */
import { InputHTMLAttributes, useEffect, useRef, useState } from 'react'
import { Eye, EyeOff } from 'lucide-react'

const CYAN = '#00F0FF'
const GLYPHS = ['▓', '█', '▒', '0xA', '0xF', '0x9']
const CYCLE_MS = 200

function Laser({ active }: { active: boolean }) {
  return (
    <span
      aria-hidden="true"
      className="pointer-events-none absolute bottom-0 left-0 right-0 h-px origin-center"
      style={{
        background: CYAN,
        boxShadow: `0 0 8px ${CYAN}`,
        transform: active ? 'scaleX(1)' : 'scaleX(0)',
        opacity: active ? 1 : 0,
        transition: 'transform 260ms cubic-bezier(0.16,1,0.3,1), opacity 260ms',
      }}
    />
  )
}

function Label({ children }: { children: React.ReactNode }) {
  return (
    <span className="mb-1.5 block font-mono text-[10px] uppercase tracking-[0.2em] text-white/40">
      {children}
    </span>
  )
}

const inputCls =
  'onus-hud-input w-full rounded-none bg-transparent px-0 py-2.5 font-mono text-[14px] text-white outline-none placeholder:text-white/20'

export function KineticField({ label, id, ...props }: InputHTMLAttributes<HTMLInputElement> & { label: string }) {
  const [focused, setFocused] = useState(false)
  return (
    <label htmlFor={id} className="mb-5 block">
      <Label>{label}</Label>
      <div className="relative" style={{ borderBottom: '1px solid rgba(255,255,255,0.12)' }}>
        <input id={id} className={inputCls} onFocus={() => setFocused(true)} onBlur={() => setFocused(false)} {...props} />
        <Laser active={focused} />
      </div>
    </label>
  )
}

export function KineticPassword({
  label, id, value, onChange, ...props
}: InputHTMLAttributes<HTMLInputElement> & { label: string }) {
  const [focused, setFocused] = useState(false)
  const [show, setShow] = useState(false)
  const [, force] = useState(0)
  const addedAt = useRef<number[]>([]) // per-index timestamp a char was added
  const val = String(value ?? '')

  // keep the timestamp array aligned with the value length
  const onChangeWrap = (e: React.ChangeEvent<HTMLInputElement>) => {
    const next = e.target.value
    const prevLen = addedAt.current.length
    if (next.length > prevLen) {
      const now = performance.now()
      for (let i = prevLen; i < next.length; i++) addedAt.current[i] = now
    } else {
      addedAt.current.length = next.length
    }
    onChange?.(e)
  }

  // while any char is still within its cycle window, re-render to animate it
  useEffect(() => {
    let raf = 0
    const tick = () => {
      const now = performance.now()
      if (addedAt.current.some((ts) => now - ts < CYCLE_MS)) {
        force((n) => n + 1)
        raf = requestAnimationFrame(tick)
      }
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [val])

  const rendered = show
    ? val
    : val
        .split('')
        .map((_, i) =>
          performance.now() - (addedAt.current[i] ?? 0) < CYCLE_MS
            ? GLYPHS[Math.floor(Math.random() * GLYPHS.length)]
            : '*',
        )
        .join('')

  return (
    <label htmlFor={id} className="mb-5 block">
      <Label>{label}</Label>
      <div className="relative" style={{ borderBottom: '1px solid rgba(255,255,255,0.12)' }}>
        {/* real input drives value + caret but is transparent; overlay shows the cycled glyphs */}
        <input
          id={id}
          type="text"
          value={val}
          onChange={onChangeWrap}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          autoComplete="off"
          spellCheck={false}
          className={`${inputCls} pr-8`}
          style={{ color: 'transparent', caretColor: CYAN }}
          {...props}
        />
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-0 flex items-center py-2.5 font-mono text-[14px] tracking-[0.15em] text-white"
        >
          {rendered || <span className="text-white/20 tracking-normal">{props.placeholder}</span>}
        </div>
        <button
          type="button"
          onClick={() => setShow((s) => !s)}
          aria-label={show ? 'Hide' : 'Show'}
          className="absolute right-0 top-1/2 -translate-y-1/2 p-1 text-white/30 transition-colors hover:text-white/70"
        >
          {show ? <EyeOff size={15} /> : <Eye size={15} />}
        </button>
        <Laser active={focused} />
      </div>
    </label>
  )
}
