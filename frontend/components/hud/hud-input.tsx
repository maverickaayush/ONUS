'use client'

/**
 * Auth inputs.
 *
 * KineticPassword used to render a FAKE mask: the real <input> was set to
 * `color: transparent` and an overlay drew each character, cycling it through
 * `['▓','█','▒','0xA','0xF','0x9']` for ~200ms before settling on '*'. That is
 * where the "0xF0x9" and filled-block glyphs came from - literal three-character
 * strings from a leftover HUD animation, not a font failing to resolve a mask
 * character. The font stack was never involved, so swapping it would have fixed
 * nothing.
 *
 * It is now a real `type="password"` input. The browser draws its own mask, so
 * it renders correctly everywhere, password managers and autofill work, and the
 * value is never mirrored into a second DOM node.
 */
import { InputHTMLAttributes, useState } from 'react'
import { Eye, EyeOff } from 'lucide-react'

function Label({ children }: { children: React.ReactNode }) {
  return <span className="mb-2 block text-[13px] font-semibold text-ink-dim">{children}</span>
}

const inputCls =
  'onus-auth-input w-full rounded-[6px] px-3.5 py-3 text-[15px] text-ink outline-none placeholder:text-ink-faint'

export function KineticField({ label, id, ...props }: InputHTMLAttributes<HTMLInputElement> & { label: string }) {
  return (
    <label htmlFor={id} className="mb-5 block">
      <Label>{label}</Label>
      <input id={id} className={inputCls} {...props} />
    </label>
  )
}

export function KineticPassword({
  label,
  id,
  ...props
}: InputHTMLAttributes<HTMLInputElement> & { label: string }) {
  const [show, setShow] = useState(false)
  return (
    <label htmlFor={id} className="mb-5 block">
      <Label>{label}</Label>
      <div className="relative">
        <input
          id={id}
          type={show ? 'text' : 'password'}
          autoComplete="current-password"
          className={`${inputCls} pr-11`}
          {...props}
        />
        <button
          type="button"
          onClick={() => setShow((s) => !s)}
          aria-label={show ? 'Hide password' : 'Show password'}
          aria-pressed={show}
          className="absolute right-1 top-1/2 -translate-y-1/2 rounded-[4px] p-2 text-ink-faint transition-colors hover:text-ink"
        >
          {show ? <EyeOff size={16} /> : <Eye size={16} />}
        </button>
      </div>
    </label>
  )
}
