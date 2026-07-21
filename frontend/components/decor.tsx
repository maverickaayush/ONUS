/**
 * Decorative collage layer for the marketing landing.
 *
 * Every export here is presentational only: `aria-hidden`, `pointer-events-none`,
 * and absolutely positioned inside a `.sec` (which is `overflow-x: clip`, so a
 * motif hanging off the edge is clipped rather than widening the page). Nothing
 * in this file is interactive or announced to assistive tech.
 *
 * All artwork is drawn here as SVG primitives: no external assets, no stock
 * imagery, nothing fetched at runtime. The engraving feel comes from filling
 * line art with a halftone dot pattern instead of a flat colour, which is how
 * the printed-manual reference gets its duotone cutouts.
 *
 * Sizing uses viewport-relative clamps and `hidden lg:block` on the larger
 * pieces, so the collage shrinks or drops on small screens instead of clipping.
 */

type Tone = 'ink' | 'indigo' | 'rust'

const TONE: Record<Tone, string> = {
  ink: 'var(--color-ink)',
  indigo: 'var(--color-indigo)',
  rust: 'var(--color-high)',
}

/** Halftone patterns. Rendered once per page; motifs reference them by id. */
export function DecorDefs() {
  return (
    <svg aria-hidden className="pointer-events-none absolute h-0 w-0" focusable="false">
      <defs>
        {(Object.keys(TONE) as Tone[]).map((t) => (
          <pattern
            key={t}
            id={`halftone-${t}`}
            width="6"
            height="6"
            patternUnits="userSpaceOnUse"
            patternTransform="rotate(30)"
          >
            <circle cx="3" cy="3" r="1.5" fill={TONE[t]} />
          </pattern>
        ))}
        {(Object.keys(TONE) as Tone[]).map((t) => (
          <pattern
            key={`f-${t}`}
            id={`halftone-fine-${t}`}
            width="4"
            height="4"
            patternUnits="userSpaceOnUse"
            patternTransform="rotate(30)"
          >
            <circle cx="2" cy="2" r="0.85" fill={TONE[t]} />
          </pattern>
        ))}
      </defs>
    </svg>
  )
}

/*  Motifs  */

const MOTIFS = {
  /** Magnifying glass over a ruled sheet: inspection. */
  magnifier: (
    <>
      <circle cx="42" cy="40" r="24" />
      <circle cx="42" cy="40" r="18" />
      <path d="M60 58 L84 84" strokeWidth="7" strokeLinecap="round" />
      <path d="M26 40h32M42 24v32" strokeWidth="1.5" />
    </>
  ),
  /** Victorian lock escutcheon plate. */
  lockplate: (
    <>
      <path d="M50 6c22 0 34 16 34 44s-12 44-34 44S16 78 16 50 28 6 50 6Z" />
      <path d="M50 14c17 0 27 13 27 36S67 86 50 86 23 73 23 50 33 14 50 14Z" strokeWidth="1.2" />
      <circle cx="50" cy="40" r="9" />
      <path d="M46 47h8l4 22H42Z" />
      <circle cx="50" cy="16" r="2" />
      <circle cx="50" cy="84" r="2" />
    </>
  ),
  /** Circuit-board trace fragment. */
  circuit: (
    <>
      <path d="M6 26h26l12 12h30M6 60h18l14-14M50 94V64l14-14h30" strokeWidth="2.5" />
      <path d="M70 78h24M70 78 58 66" strokeWidth="2.5" />
      <circle cx="74" cy="38" r="5" />
      <circle cx="94" cy="36" r="4" />
      <circle cx="94" cy="78" r="4" />
      <circle cx="24" cy="60" r="4" />
      <rect x="30" y="18" width="16" height="16" rx="2" />
      <rect x="54" y="60" width="18" height="12" rx="2" />
    </>
  ),
  /** Manual telephone switchboard: patch jacks and cords. */
  switchboard: (
    <>
      <rect x="8" y="10" width="84" height="52" rx="3" />
      {[0, 1, 2, 3].map((r) =>
        [0, 1, 2, 3, 4].map((c) => (
          <circle key={`${r}-${c}`} cx={20 + c * 15} cy={20 + r * 12} r="3.5" />
        )),
      )}
      <path d="M20 32c0 26 18 30 30 38" strokeWidth="2.5" />
      <path d="M65 44c2 22-10 26-22 30" strokeWidth="2.5" />
      <circle cx="50" cy="72" r="4" />
      <circle cx="43" cy="76" r="4" />
    </>
  ),
  /** Compass rose / engraved starburst. */
  compass: (
    <>
      <circle cx="50" cy="50" r="38" />
      <circle cx="50" cy="50" r="30" strokeWidth="1.2" />
      <path d="M50 8 58 42 92 50 58 58 50 92 42 58 8 50 42 42Z" />
      <circle cx="50" cy="50" r="5" />
    </>
  ),
  /** Filing cabinet: archived evidence. */
  cabinet: (
    <>
      <rect x="16" y="8" width="68" height="84" rx="3" />
      {[0, 1, 2].map((i) => (
        <rect key={i} x="24" y={18 + i * 26} width="52" height="18" rx="2" />
      ))}
      {[0, 1, 2].map((i) => (
        <path key={`h-${i}`} d={`M44 ${27 + i * 26}h12`} strokeWidth="3" strokeLinecap="round" />
      ))}
    </>
  ),
  /** Surveyor's theodolite: measurement before action. */
  theodolite: (
    <>
      <path d="M50 62 22 94M50 62l28 32M50 62v-8" strokeWidth="2.5" strokeLinecap="round" />
      <rect x="34" y="34" width="32" height="20" rx="3" />
      <path d="M66 40h20M14 40h20" strokeWidth="2.5" strokeLinecap="round" />
      <circle cx="50" cy="44" r="5" />
      <path d="M50 20v10" strokeWidth="2" strokeLinecap="round" />
      <circle cx="50" cy="16" r="4" />
    </>
  ),
  /** Targeting diagram: concentric rings, crosshair, bearing ticks. */
  reticle: (
    <>
      <circle cx="50" cy="50" r="40" />
      <circle cx="50" cy="50" r="27" strokeWidth="1.4" />
      <circle cx="50" cy="50" r="13" strokeWidth="1.4" />
      <path d="M50 2v22M50 76v22M2 50h22M76 50h22" strokeWidth="2" strokeLinecap="round" />
      <circle cx="50" cy="50" r="3" />
      {[30, 60, 120, 150, 210, 240, 300, 330].map((a) => {
        const r = (a * Math.PI) / 180
        return (
          <path
            key={a}
            d={`M ${50 + 40 * Math.cos(r)} ${50 + 40 * Math.sin(r)} L ${50 + 34 * Math.cos(r)} ${50 + 34 * Math.sin(r)}`}
            strokeWidth="1.6"
            strokeLinecap="round"
          />
        )
      })}
    </>
  ),
  /** Stacked ruled index cards: the ledger of past assessments. */
  ledger: (
    <>
      <rect x="10" y="26" width="66" height="46" rx="3" />
      <rect x="18" y="18" width="66" height="46" rx="3" />
      <rect x="26" y="10" width="66" height="46" rx="3" />
      <path d="M34 24h50M34 32h50M34 40h34" strokeWidth="1.6" strokeLinecap="round" />
    </>
  ),
  /** Engraved globe: the surface being assessed. */
  globe: (
    <>
      <circle cx="50" cy="50" r="40" />
      <ellipse cx="50" cy="50" rx="16" ry="40" strokeWidth="1.4" />
      <ellipse cx="50" cy="50" rx="31" ry="40" strokeWidth="1.2" />
      <path d="M10 50h80M15 30h70M15 70h70" strokeWidth="1.4" />
      <circle cx="50" cy="50" r="3" />
    </>
  ),
  /** Old warded key: the entry point. */
  key: (
    <>
      <circle cx="26" cy="30" r="15" />
      <circle cx="26" cy="30" r="7" />
      <path d="M36 40 78 82" strokeWidth="6" strokeLinecap="round" />
      <path d="M64 68l10 10M56 60l8 8" strokeWidth="5" strokeLinecap="round" />
    </>
  ),
  /** Wax seal: an authorised, stamped record. */
  waxseal: (
    <>
      <path d="M50 8c14 2 22-2 30 8s4 18 8 28-8 16-10 28-14 12-28 12-24 2-30-8-4-18-8-28 6-18 8-28S36 6 50 8Z" />
      <circle cx="50" cy="50" r="24" strokeWidth="1.4" />
      <circle cx="50" cy="50" r="15" strokeWidth="1.2" />
      <path d="M50 38v24M38 50h24" strokeWidth="2.5" strokeLinecap="round" />
    </>
  ),
  /** Ledger stamp: serrated edge, ruled impression. */
  stamp: (
    <>
      <rect x="12" y="20" width="76" height="60" rx="2" />
      <rect x="20" y="28" width="60" height="44" rx="2" strokeWidth="1.3" />
      <path d="M30 44h40M30 54h40M30 64h24" strokeWidth="2" strokeLinecap="round" />
      {[0, 1, 2, 3, 4, 5, 6, 7].map((i) => (
        <circle key={`t-${i}`} cx={16 + i * 10} cy="20" r="1.8" />
      ))}
      {[0, 1, 2, 3, 4, 5, 6, 7].map((i) => (
        <circle key={`b-${i}`} cx={16 + i * 10} cy="80" r="1.8" />
      ))}
    </>
  ),
} as const

export type MotifKind = keyof typeof MOTIFS

/**
 * A halftone-filled engraving. `className` positions it; keep it absolute and
 * inside a `.sec` so it can never widen the page.
 */
export function Motif({
  kind,
  className = '',
  tone = 'ink',
  rotate = 0,
  opacity = 0.14,
}: {
  kind: MotifKind
  className?: string
  tone?: Tone
  rotate?: number
  opacity?: number
}) {
  return (
    <svg
      aria-hidden
      focusable="false"
      viewBox="0 0 100 100"
      className={`pointer-events-none absolute select-none ${className}`}
      style={{ transform: `rotate(${rotate}deg)`, opacity }}
    >
      <g
        fill={`url(#halftone-${tone})`}
        stroke={TONE[tone]}
        strokeWidth="2"
        strokeLinejoin="round"
      >
        {MOTIFS[kind]}
      </g>
    </svg>
  )
}

/*  Halftone plates  */

/**
 * An aged halftone cutout. These are raster plates (public/decor/*.png), not
 * SVG line art: each is rendered from a continuous-tone greyscale source and
 * screened through a real AM halftone, so dot size tracks local darkness and
 * the result carries actual tonal range. That is the asset class the printed
 * reference uses, and it is why these are not simply more Motif entries.
 *
 * Purely presentational: aria-hidden, pointer-events-none, and a static image,
 * so prefers-reduced-motion is satisfied by construction.
 */
export function Plate({
  src,
  className = '',
  rotate = 0,
  opacity = 0.22,
  delay = 0,
}: {
  src: string
  className?: string
  rotate?: number
  opacity?: number
  delay?: number
}) {
  return (
    <img
      src={`/decor/${src}.png`}
      alt=""
      aria-hidden
      draggable={false}
      className={`plate-drift pointer-events-none absolute select-none ${className}`}
      style={{ ['--rot' as string]: `${rotate}deg`, transform: `rotate(${rotate}deg)`, opacity,
               animationDelay: `${delay}s` }}
    />
  )
}

/*  Sunburst  */

/**
 * Radiating hand-drawn dashes around a word. Rendered as an absolutely
 * positioned sibling rather than a CSS pseudo-element so the ray length can
 * follow the word's aspect ratio: a circular burst around a wide word puts
 * dashes straight through the letterforms.
 */
export function Sunburst({
  className = '',
  rays = 22,
  tone = 'rust',
}: {
  className?: string
  rays?: number
  tone?: Tone
}) {
  const marks = Array.from({ length: rays }, (_, i) => {
    const a = (i / rays) * Math.PI * 2
    // jitter keeps it hand-drawn rather than machine-perfect
    const inner = 33 + ((i * 7) % 5)
    const outer = 45 + ((i * 11) % 7)
    return {
      x1: 50 + inner * Math.cos(a),
      y1: 50 + inner * Math.sin(a) * 0.62,
      x2: 50 + outer * Math.cos(a),
      y2: 50 + outer * Math.sin(a) * 0.62,
    }
  })
  return (
    <svg
      aria-hidden
      focusable="false"
      viewBox="0 0 100 100"
      preserveAspectRatio="none"
      className={`pointer-events-none absolute select-none ${className}`}
    >
      {marks.map((m, i) => (
        <line
          key={i}
          {...m}
          stroke={TONE[tone]}
          strokeWidth="1.6"
          strokeLinecap="round"
          opacity={0.75}
        />
      ))}
    </svg>
  )
}

/*  Hand-drawn annotations  */

/** Loose double underline, as if drawn under a phrase with a marker. */
export function Underline({ className = '', tone = 'indigo' }: { className?: string; tone?: Tone }) {
  return (
    <svg
      aria-hidden
      focusable="false"
      viewBox="0 0 200 14"
      preserveAspectRatio="none"
      className={`pointer-events-none absolute select-none ${className}`}
    >
      <path
        d="M3 7C40 2 92 11 139 5c22-3 40 1 58 3"
        fill="none"
        stroke={TONE[tone]}
        strokeWidth="2.6"
        strokeLinecap="round"
      />
      <path
        d="M12 12c46-5 96 3 140-2"
        fill="none"
        stroke={TONE[tone]}
        strokeWidth="1.5"
        strokeLinecap="round"
        opacity="0.6"
      />
    </svg>
  )
}

/** Curved arrow with a hand-drawn head. `flip` mirrors it horizontally. */
export function Arrow({
  className = '',
  tone = 'ink',
  flip = false,
}: {
  className?: string
  tone?: Tone
  flip?: boolean
}) {
  return (
    <svg
      aria-hidden
      focusable="false"
      viewBox="0 0 120 90"
      className={`pointer-events-none absolute select-none ${className}`}
      style={flip ? { transform: 'scaleX(-1)' } : undefined}
    >
      <g fill="none" stroke={TONE[tone]} strokeWidth="2.6" strokeLinecap="round">
        <path d="M8 10c34 4 62 22 78 56" />
        <path d="M70 62l17 6M86 68l4-18" />
      </g>
    </svg>
  )
}

/** Loose ellipse drawn around a phrase, slightly overshooting like a real pen. */
export function CircleMark({ className = '', tone = 'rust' }: { className?: string; tone?: Tone }) {
  return (
    <svg
      aria-hidden
      focusable="false"
      viewBox="0 0 200 70"
      preserveAspectRatio="none"
      className={`pointer-events-none absolute select-none ${className}`}
    >
      <path
        d="M104 5C48 3 8 17 6 35c-2 19 44 31 98 30 52-1 90-14 90-31 0-16-36-28-88-29-14 0-28 1-40 4"
        fill="none"
        stroke={TONE[tone]}
        strokeWidth="2.4"
        strokeLinecap="round"
        opacity="0.85"
      />
    </svg>
  )
}

/*  Seal  */

/**
 * Tilted circular sticker, the printed-seal equivalent of a trust badge.
 * The rim text is set on a circular path so it reads around the edge.
 */
export function Seal({ className = '', rotate = -9 }: { className?: string; rotate?: number }) {
  return (
    <svg
      aria-hidden
      focusable="false"
      viewBox="0 0 120 120"
      className={`pointer-events-none absolute select-none ${className}`}
      style={{ transform: `rotate(${rotate}deg)` }}
    >
      <circle cx="60" cy="60" r="57" fill="var(--color-lime)" stroke="var(--color-ink)" strokeWidth="3" />
      <circle cx="60" cy="60" r="44" fill="none" stroke="var(--color-ink)" strokeWidth="1.4" />
      <defs>
        <path id="seal-rim" d="M60 10a50 50 0 1 1-0.1 0" fill="none" />
      </defs>
      <text
        fill="var(--color-ink)"
        fontSize="10.5"
        fontWeight="700"
        letterSpacing="2.6"
        fontFamily="var(--font-sans)"
      >
        <textPath href="#seal-rim" startOffset="0%">
          AUTHORIZED SCANS ONLY · EVIDENCE DECIDES ·
        </textPath>
      </text>
      <text
        x="60"
        y="55"
        textAnchor="middle"
        fill="var(--color-ink)"
        fontSize="19"
        fontWeight="700"
        fontFamily="var(--font-display)"
      >
        CVSS
      </text>
      <text
        x="60"
        y="73"
        textAnchor="middle"
        fill="var(--color-ink)"
        fontSize="13"
        fontWeight="700"
        letterSpacing="1.5"
        fontFamily="var(--font-sans)"
      >
        v3.1
      </text>
    </svg>
  )
}
