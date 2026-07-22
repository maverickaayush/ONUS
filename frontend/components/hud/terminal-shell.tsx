'use client'

/**
 * Shared ONUS auth chrome for /sign-in and /sign-up, so both read as the same
 * surface: ONUS emblem anchor, neo-brutalist card on printed paper, footer
 * attribution. Pages supply only the form as children + drive `verified`.
 *
 * DIRECTION C note: the previous build wrapped this in a cold-boot HUD (particle
 * canvas, targeting-reticle cursor, hex stream, oscilloscope, giant wireframe
 * emblem). Those were decoration tied to the dark console language and are gone;
 * every functional element (submit, error slot, verified state) is preserved.
 */
import { ReactNode } from 'react'
import { motion } from 'motion/react'
import { OnusMark } from '@/components/ui'
import { Plate, Seal } from '@/components/decor'

/**
 * Primary auth action. Previously scrambled its own label through a random
 * character set on hover - a HUD-era effect that turned sentence-case copy
 * ("Sign in") into noise and read as a rendering glitch. Now a plain button;
 * the name is kept because both auth pages import it.
 */
export function ScrambleButton({ label, disabled, onClick, type = 'button' }: {
  label: string; disabled?: boolean; onClick?: () => void; type?: 'button' | 'submit'
}) {
  return (
    <button
      type={type}
      disabled={disabled}
      onClick={onClick}
      className="onus-auth-btn mt-3 w-full rounded-[6px] py-3.5 text-[15px] font-bold disabled:cursor-not-allowed disabled:opacity-40"
    >
      {label}
    </button>
  )
}

function EmblemHeader({ subtitle, verified }: { subtitle: string; verified?: boolean }) {
  return (
    <div className="mb-8 flex flex-col items-center">
      <motion.span
        className="flex h-16 w-16 items-center justify-center rounded-[8px] border-2 border-border bg-lime"
        style={{ boxShadow: 'var(--shadow-hard-lg)' }}
        animate={verified ? { rotate: [0, -4, 4, 0] } : {}}
        transition={{ duration: 0.9, repeat: verified ? Infinity : 0 }}
      >
        <OnusMark className="h-8 w-8 text-ink" />
      </motion.span>
      <h1 className="display mt-6 text-[38px] leading-none text-ink">ONUS</h1>
      <p className="mt-3 text-[15px] text-ink-dim">{subtitle}</p>
    </div>
  )
}

export function TerminalShell({ subtitle, verified, children }: {
  subtitle: string; verified?: boolean; children: ReactNode
}) {
  return (
    // sec + sec-lilac supplies the tinted graph-paper overlay every other
    // section carries. Everything decorative below is static SVG: this page had
    // a decorative animation break the password field once, so nothing here
    // animates and reduced-motion is respected by construction.
    <div
      className="sec sec-lilac relative flex min-h-screen items-center justify-center overflow-x-clip"
      style={{
        paddingLeft: 'max(1.25rem, env(safe-area-inset-left))',
        paddingRight: 'max(1.25rem, env(safe-area-inset-right))',
        paddingTop: 'max(3rem, env(safe-area-inset-top))',
        paddingBottom: 'max(3.5rem, env(safe-area-inset-bottom))',
      }}
    >
      {/* Three riso plates: greyscale halftone with flat spot-colour blocks
          beneath, the technique the printed reference uses. Margins only, 2xl,
          and none within reach of the form or the password field. */}
      <Plate src="filing-cabinet" rotate={-6} opacity={0.26} delay={0}
        className="left-[2%] top-1/2 hidden h-[420px] w-[420px] -translate-y-1/2 2xl:block" />
      <Plate src="old-key" rotate={9} opacity={0.28} delay={2.5}
        className="right-[3%] top-[12%] hidden h-[300px] w-[300px] 2xl:block" />
      <Plate src="rotary-phone" rotate={-4} opacity={0.24} delay={5}
        className="bottom-[6%] right-[6%] hidden h-[300px] w-[300px] 2xl:block" />

      <div className="relative z-10 w-full max-w-[440px]">
        <EmblemHeader subtitle={subtitle} verified={verified} />
        <div className="relative">
          {/* Tilted seal tucked behind the card's top-right corner, the way the
              landing hero uses stickers. Behind the card, clear of every input. */}
          <Seal className="-right-14 -top-12 z-20 hidden h-[112px] w-[112px] lg:block" rotate={14} />
          {/* 1.2deg tilt so the card reads as a placed sheet rather than a
              flat modal. Small enough not to disturb input hit areas. */}
          <div className="brut relative z-10 p-8" style={{ rotate: '-1.2deg' }}>
            <div style={{ rotate: '1.2deg' }}>{children}</div>
          </div>
        </div>
        <p className="mt-7 text-center text-[13.5px] text-ink-dim">
          <a href="/" className="border-b-2 border-border pb-0.5 font-semibold text-ink hover:text-accent">
            Back to onus.
          </a>
        </p>
      </div>

      <p
        className="pointer-events-none fixed z-20 font-mono text-[10px] text-ink-faint"
        style={{
          bottom: 'max(0.6rem, env(safe-area-inset-bottom))',
          left: 'max(0.75rem, env(safe-area-inset-left))',
        }}
      >
        Developed by maverickaayush | Report by ONUS
      </p>
    </div>
  )
}

export function TerminalError({ children }: { children: ReactNode }) {
  if (!children) return null
  return (
    <p
      role="alert"
      className="mb-5 rounded-[6px] border-2 border-crit bg-crit/[0.08] px-3.5 py-2.5 text-[13px] font-medium text-crit"
    >
      {children}
    </p>
  )
}
