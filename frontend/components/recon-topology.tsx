'use client'

/**
 * Recon topology: the discovered host graph for a scan.
 *
 * WHAT THE DATA ACTUALLY SUPPORTS (checked against live scan output, not assumed):
 *   - Hosts come from recon findings titled "Subdomain discovered: <host>".
 *   - Per-host open ports are REAL: recon emits "Open port <n> on <host>" with
 *     evidence "<host>:<port>", so the host->port association is a genuine join.
 *   - Live/HTTP status is real: "Live subdomain: https://<host>" + evidence.
 *   - IP is available for the APEX ONLY ("A record found for <domain>"). Sub-
 *     domains carry no per-host IP anywhere in the payload, so the detail card
 *     shows an IP row for the apex and omits it for subdomains rather than
 *     inventing one.
 *   - There is NO bare-IP host in the data, so nodes are tinted by role
 *     (apex vs subdomain). A third "bare IP" role would never render.
 *
 * WHAT IT DOES NOT SUPPORT: findings carry no host/target field
 * (GET /api/scan/{id}/findings returns title/evidence/module/severity/... and
 * nothing identifying a host). Host->finding association is therefore a TEXT
 * MATCH over title+evidence, not a join, and is labelled as such in the UI.
 */
import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { DecorDefs, Motif } from './decor'

export interface TopoFinding {
  title: string
  evidence: string
  module: string
}

export interface HostNode {
  host: string
  label: string
  role: 'apex' | 'subdomain'
  ports: number[]
  live?: string
  ip?: string
  mentions: number
  x: number
  y: number
  lx: number
  ly: number
  side: 1 | -1
}

const W = 860
const PAD_X = 190 // reserved for the label columns; nothing draws inside it
const PAD_Y = 54
const MIN_GAP = 17 // minimum vertical clearance between two labels
const LABEL_X_R = W - PAD_X + 34
const LABEL_X_L = PAD_X - 34

/** Canvas height grows with host count so the two label columns always have
 *  room for MIN_GAP spacing. A fixed height is what forced labels to collide
 *  once the graph passed ~20 hosts. */
function canvasHeight(n: number) {
  return Math.max(520, Math.ceil(Math.max(0, n - 1) / 2) * MIN_GAP + 150)
}

/* ── data extraction ────────────────────────────────────────────────────── */

function esc(s: string) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

export function buildHosts(findings: TopoFinding[], domain: string): HostNode[] {
  const base = domain.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '')
  const blob = findings.map((f) => `${f.title} ${f.evidence}`).join('\n').toLowerCase()

  const hostRe = new RegExp(`\\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+${esc(base)})\\b`, 'gi')
  const subs = new Set<string>()
  for (const f of findings) {
    if (f.module !== 'recon' || !/subdomain/i.test(f.title)) continue
    for (const m of `${f.title} ${f.evidence}`.match(hostRe) || []) {
      const h = m.toLowerCase()
      if (h !== base) subs.add(h)
    }
  }

  const apexIp = blob.match(
    new RegExp(`${esc(base)}[^\\n]*?\\b((?:\\d{1,3}\\.){3}\\d{1,3})\\b`, 'i'),
  )?.[1]

  const mk = (host: string, role: 'apex' | 'subdomain'): HostNode => {
    const portRe = new RegExp(`${esc(host)}[:\\s]+(?:port\\s+)?(\\d{2,5})`, 'gi')
    const onRe = new RegExp(`open port\\s+(\\d{2,5})\\s+on\\s+${esc(host)}`, 'gi')
    const ports = new Set<number>()
    for (const re of [portRe, onRe])
      for (const m of blob.matchAll(re)) ports.add(Number(m[1]))
    const live = findings.find(
      (f) => /live subdomain/i.test(f.title) && f.title.toLowerCase().includes(host),
    )?.evidence
    const mentions = findings.filter((f) =>
      `${f.title} ${f.evidence}`.toLowerCase().includes(host),
    ).length
    return {
      host,
      label: role === 'apex' ? host : host.slice(0, host.length - base.length - 1) || host,
      role,
      ports: [...ports].sort((a, b) => a - b),
      live,
      ip: role === 'apex' ? apexIp : undefined,
      mentions,
      x: 0, y: 0, lx: 0, ly: 0, side: 1,
    }
  }

  return [mk(base, 'apex'), ...[...subs].sort().map((h) => mk(h, 'subdomain'))]
}

/* ── layout ─────────────────────────────────────────────────────────────── */

/**
 * Fruchterman-Reingold force-directed layout, run to convergence synchronously.
 *
 * Chosen over a fixed radial ring because the ring hard-codes the shape: it
 * assumes exactly one centre and evenly spaced leaves, and degenerates into
 * unreadable overlap past ~20 nodes. FR derives position from the edge set, so
 * it handles 4 hosts and 40 with the same code, and would keep working if recon
 * ever emits deeper structure (a subdomain of a subdomain) without a rewrite.
 *
 * Seeded deterministically from a golden-angle spiral, so the same scan always
 * renders the same picture. No animation loop: the simulation is finished
 * before first paint, which is also what makes it reduced-motion safe.
 */
function layout(nodes: HostNode[], H: number): HostNode[] {
  const n = nodes.length
  if (n === 0) return nodes
  const iw = W - PAD_X * 2
  const ih = H - PAD_Y * 2
  const cx = W / 2
  const cy = H / 2
  if (n === 1) return [{ ...nodes[0], x: cx, y: cy, lx: cx, ly: cy + 40, side: 1 }]

  const k = Math.sqrt((iw * ih) / n) * 0.72
  const GA = Math.PI * (3 - Math.sqrt(5))
  const p = nodes.map((_, i) => {
    if (i === 0) return { x: cx, y: cy }
    const r = (Math.sqrt(i / (n - 1)) * Math.min(iw, ih)) / 2.1
    return { x: cx + r * Math.cos(i * GA), y: cy + r * Math.sin(i * GA) }
  })

  const ITER = 420
  for (let it = 0; it < ITER; it++) {
    const temp = (Math.min(iw, ih) / 8) * (1 - it / ITER) + 0.4
    const disp = p.map(() => ({ x: 0, y: 0 }))

    for (let i = 0; i < n; i++)
      for (let j = i + 1; j < n; j++) {
        let dx = p[i].x - p[j].x
        let dy = p[i].y - p[j].y
        let d = Math.hypot(dx, dy)
        if (d < 0.01) { dx = (i % 3) - 1 + 0.1; dy = (j % 3) - 1 + 0.1; d = Math.hypot(dx, dy) }
        const rep = (k * k) / d
        disp[i].x += (dx / d) * rep; disp[i].y += (dy / d) * rep
        disp[j].x -= (dx / d) * rep; disp[j].y -= (dy / d) * rep
      }

    // every subdomain is joined to the apex (index 0)
    for (let i = 1; i < n; i++) {
      const dx = p[i].x - p[0].x
      const dy = p[i].y - p[0].y
      const d = Math.max(0.01, Math.hypot(dx, dy))
      const att = (d * d) / k
      disp[i].x -= (dx / d) * att; disp[i].y -= (dy / d) * att
      disp[0].x += (dx / d) * att; disp[0].y += (dy / d) * att
    }

    for (let i = 0; i < n; i++) {
      // weak gravity keeps disconnected clusters from drifting off-canvas
      disp[i].x += (cx - p[i].x) * 0.012
      disp[i].y += (cy - p[i].y) * 0.012
      const d = Math.max(0.01, Math.hypot(disp[i].x, disp[i].y))
      const lim = Math.min(d, temp)
      if (i === 0 && n > 2) continue // pin the apex; it is the anchor of the story
      p[i].x += (disp[i].x / d) * lim
      p[i].y += (disp[i].y / d) * lim
    }
  }

  // normalise into the padded viewBox
  const xs = p.map((q) => q.x), ys = p.map((q) => q.y)
  const minX = Math.min(...xs), maxX = Math.max(...xs)
  const minY = Math.min(...ys), maxY = Math.max(...ys)
  const sx = maxX - minX < 1 ? 1 : iw / (maxX - minX)
  const sy = maxY - minY < 1 ? 1 : ih / (maxY - minY)
  const s = Math.min(sx, sy)
  const ox = PAD_X + (iw - (maxX - minX) * s) / 2
  const oy = PAD_Y + (ih - (maxY - minY) * s) / 2

  const placed = nodes.map((nd, i) => ({
    ...nd,
    x: ox + (p[i].x - minX) * s,
    y: oy + (p[i].y - minY) * s,
  }))

  return declutterLabels(placed, H)
}

/**
 * Label collision avoidance. Labels sit outboard of their node (left of nodes
 * on the left half, right of nodes on the right half). Within each side they
 * are sorted by y and pushed apart until every pair clears MIN_GAP, then the
 * whole column is nudged back inside the viewBox. Where a label ends up more
 * than LEADER px off its node, the renderer draws a leader line so the pairing
 * stays unambiguous. Without this, 40 hosts overlap into an unreadable smear.
 */
const LEADER = 3

function declutterLabels(nodes: HostNode[], H: number): HostNode[] {
  const out = nodes.map((n) => ({ ...n }))
  const cx = W / 2
  for (const n of out) {
    n.side = n.x >= cx ? 1 : -1
    // Every label on a side shares one x. Anchoring each label at its own
    // node's x (the previous approach) meant two labels could still overlap
    // horizontally even after vertical separation, which is exactly what went
    // wrong at 40 hosts.
    n.lx = n.side === 1 ? LABEL_X_R : LABEL_X_L
    n.ly = n.y
  }
  for (const side of [1, -1] as const) {
    const col = out.filter((n) => n.side === side && n.role !== 'apex').sort((a, b) => a.ly - b.ly)
    for (let pass = 0; pass < 200; pass++) {
      let moved = false
      for (let i = 1; i < col.length; i++) {
        const gap = col[i].ly - col[i - 1].ly
        if (gap < MIN_GAP) {
          const push = (MIN_GAP - gap) / 2
          col[i - 1].ly -= push
          col[i].ly += push
          moved = true
        }
      }
      if (!moved) break
    }
    if (col.length) {
      // clamp the whole column inside the canvas, preserving spacing
      const top = Math.min(...col.map((c) => c.ly))
      const bot = Math.max(...col.map((c) => c.ly))
      const shift = top < 16 ? 16 - top : bot > H - 16 ? H - 16 - bot : 0
      for (const c of col) c.ly += shift
    }
  }
  return out
}

/* ── curve ──────────────────────────────────────────────────────────────── */

/** Quadratic curve with a deterministic perpendicular bow, so edges read as
 *  drawn by hand rather than plotted. Bow direction alternates by index. */
function edgePath(ax: number, ay: number, bx: number, by: number, i: number) {
  const mx = (ax + bx) / 2
  const my = (ay + by) / 2
  const dx = bx - ax
  const dy = by - ay
  const len = Math.max(1, Math.hypot(dx, dy))
  const bow = (i % 2 === 0 ? 1 : -1) * Math.min(26, len * 0.13)
  return `M ${ax} ${ay} Q ${mx + (-dy / len) * bow} ${my + (dx / len) * bow} ${bx} ${by}`
}

/* ── component ──────────────────────────────────────────────────────────── */

export function ReconTopology({
  findings,
  domain,
  onSelectHost,
  selectedHost,
}: {
  findings: TopoFinding[]
  domain: string
  onSelectHost?: (host: string | null) => void
  selectedHost?: string | null
}) {
  const uid = useId().replace(/:/g, '')
  const [active, setActive] = useState<string | null>(null)
  const [reduced, setReduced] = useState(false)
  const svgRef = useRef<SVGSVGElement>(null)

  useEffect(() => {
    const m = window.matchMedia('(prefers-reduced-motion: reduce)')
    const on = () => setReduced(m.matches)
    on()
    m.addEventListener('change', on)
    return () => m.removeEventListener('change', on)
  }, [])

  const { nodes, H } = useMemo(() => {
    const raw = buildHosts(findings, domain)
    const h = canvasHeight(raw.length)
    return { nodes: layout(raw, h), H: h }
  }, [findings, domain])
  const apex = nodes[0]
  const subs = nodes.slice(1)
  const shown = active ?? selectedHost ?? null
  const detail = nodes.find((n) => n.host === shown) ?? null

  const summary = useMemo(() => {
    if (!apex) return ''
    if (!subs.length) return `Recon found no additional hosts beyond ${apex.host}.`
    return (
      `Host graph for ${apex.host}: ${subs.length} discovered subdomain` +
      `${subs.length === 1 ? '' : 's'}. ` +
      subs
        .map((s) => `${s.host}${s.ports.length ? ` (open ports ${s.ports.join(', ')})` : ''}`)
        .join('; ') + '.'
    )
  }, [apex, subs])

  if (!apex) return null

  /* Empty state: a single host is a legitimate recon result, not a failure. */
  if (subs.length === 0) {
    return (
      <section className="mt-8" aria-labelledby={`${uid}-h`}>
        <Head id={`${uid}-h`} count={1} />
        <div className="brut relative flex flex-col items-center gap-3 overflow-hidden px-6 py-14 text-center">
          <DecorDefs />
          {/* A single host is a real result, so the panel gets composed art
              rather than reading as a failed render. Anchored on the node badge,
              not the panel centre: centred, its rings ran straight through the
              explanatory copy below. */}
          <Motif kind="reticle" tone="ink" rotate={0} opacity={0.1}
            className="left-1/2 top-[70px] h-[168px] w-[168px] -translate-x-1/2 -translate-y-1/2" />
          <NodeBadge role="apex" />
          <p className="relative font-mono text-[15px] font-semibold text-ink">{apex.host}</p>
          <p className="relative max-w-[46ch] text-[13.5px] leading-relaxed text-ink-dim">
            No additional hosts were discovered. Recon resolved this target to a single
            host, so there is no graph to draw{apex.ip ? ` (${apex.ip})` : ''}.
          </p>
          {apex.ports.length > 0 && (
            <p className="relative font-mono text-[12.5px] text-ink-faint">
              Open ports: {apex.ports.join(' · ')}
            </p>
          )}
        </div>
      </section>
    )
  }

  // The apex never dims: every highlighted edge terminates on it, so fading it
  // leaves a lit edge running into a greyed-out node.
  const dim = (host: string) => shown !== null && shown !== host && host !== apex.host

  return (
    <section className="mt-8" aria-labelledby={`${uid}-h`}>
      <Head id={`${uid}-h`} count={nodes.length} />

      {/* Text equivalent: the graph is decorative to a screen reader, so the
          same information is given as prose plus a real list. */}
      <p className="sr-only">{summary}</p>

      <div className="brut relative overflow-hidden">
        <svg
          ref={svgRef}
          viewBox={`0 0 ${W} ${H}`}
          className="h-auto w-full"
          role="group"
          aria-label={`Host graph. ${summary}`}
          onMouseLeave={() => setActive(null)}
        >
          {/* edges */}
          <g fill="none">
            {subs.map((s, i) => {
              const on = shown === null || shown === s.host
              return (
                <path
                  key={s.host}
                  d={edgePath(apex.x, apex.y, s.x, s.y, i)}
                  stroke="var(--color-ink)"
                  strokeWidth={shown === s.host ? 2.6 : 1.6}
                  strokeLinecap="round"
                  opacity={on ? 0.75 : 0.12}
                  style={reduced ? undefined : { transition: 'opacity 160ms, stroke-width 160ms' }}
                />
              )
            })}
          </g>

          {/* leader lines where a label was displaced to avoid collision */}
          <g>
            {subs.map((s) =>
              Math.abs(s.ly - s.y) > LEADER || Math.abs(s.lx - s.x) > 24 ? (
                <path
                  key={`l-${s.host}`}
                  d={`M ${s.x + s.side * 13} ${s.y} L ${s.lx - s.side * 7} ${s.ly}`}
                  stroke="var(--color-ink)"
                  strokeWidth="1"
                  opacity={dim(s.host) ? 0.1 : 0.35}
                  fill="none"
                />
              ) : null,
            )}
          </g>

          {/* nodes */}
          {nodes.map((n) => {
            const isApex = n.role === 'apex'
            const r = isApex ? 17 : 10
            const faded = dim(n.host)
            return (
              <g
                key={n.host}
                opacity={faded ? 0.3 : 1}
                style={reduced ? undefined : { transition: 'opacity 160ms' }}
              >
                {/* hard offset shadow, drawn as a duplicate behind the shape */}
                <circle cx={n.x + 3} cy={n.y + 3} r={r} fill="var(--color-ink)" />
                <circle
                  cx={n.x}
                  cy={n.y}
                  r={r}
                  fill={isApex ? 'var(--color-lime)' : 'var(--color-mint)'}
                  stroke="var(--color-ink)"
                  strokeWidth="2.5"
                />
                {selectedHost === n.host && (
                  <circle
                    cx={n.x}
                    cy={n.y}
                    r={r + 6}
                    fill="none"
                    stroke="var(--color-ink)"
                    strokeWidth="1.5"
                    strokeDasharray="3 3"
                  />
                )}
                {n.mentions > 0 && !isApex && (
                  <>
                    <circle cx={n.x + r - 1} cy={n.y - r + 1} r="7" fill="var(--color-ink)" />
                    <text
                      x={n.x + r - 1}
                      y={n.y - r + 4}
                      textAnchor="middle"
                      className="font-mono"
                      style={{ fontSize: 9, fontWeight: 700, fill: 'var(--color-panel)' }}
                    >
                      {n.mentions > 9 ? '9+' : n.mentions}
                    </text>
                  </>
                )}
                <text
                  x={isApex ? n.x : n.lx}
                  y={isApex ? n.y + r + 17 : n.ly + 4}
                  textAnchor={isApex ? 'middle' : n.side === 1 ? 'start' : 'end'}
                  className="font-mono"
                  style={{
                    fontSize: isApex ? 13 : 11.5,
                    fontWeight: isApex ? 700 : 500,
                    fill: 'var(--color-ink)',
                    paintOrder: 'stroke',
                    stroke: 'var(--color-canvas)',
                    strokeWidth: 3,
                    strokeLinejoin: 'round',
                  }}
                >
                  {n.label}
                </text>
                {/* Dedicated hit target. The visual <g> spans from the node to
                    its label column, so its geometric centre is empty canvas and
                    pointer events landed on the backdrop instead of the node. */}
                <circle
                  cx={n.x}
                  cy={n.y}
                  r={r + 7}
                  fill="transparent"
                  role="button"
                  tabIndex={0}
                  aria-label={`${n.host}, ${n.role}${
                    n.ports.length ? `, open ports ${n.ports.join(', ')}` : ''
                  }, ${n.mentions} findings mention this host. Activate to filter the findings table.`}
                  className="cursor-pointer outline-none focus-visible:stroke-[var(--color-ink)]"
                  style={{ pointerEvents: 'all' }}
                  strokeWidth={3}
                  onMouseEnter={() => setActive(n.host)}
                  onFocus={() => setActive(n.host)}
                  onBlur={() => setActive(null)}
                  onClick={() => onSelectHost?.(selectedHost === n.host ? null : n.host)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault()
                      onSelectHost?.(selectedHost === n.host ? null : n.host)
                    }
                  }}
                />
              </g>
            )
          })}
        </svg>

        {/* Detail card. Anchored in the corner rather than following the cursor:
            a floating card near an edge node would overflow the panel on narrow
            viewports, and this stays put for keyboard users too. */}
        {detail && (
          <div className="pointer-events-none absolute left-3 top-3 max-w-[260px] rounded-[6px] border-2 border-border bg-panel p-3.5 shadow-[3px_3px_0_var(--color-ink)]">
            <p className="break-all font-mono text-[12.5px] font-bold text-ink">{detail.host}</p>
            <dl className="mt-2 space-y-1 text-[11.5px]">
              <Row k="Role" v={detail.role === 'apex' ? 'Apex domain' : 'Subdomain'} />
              {detail.ip && <Row k="IP" v={detail.ip} mono />}
              <Row k="Open ports" v={detail.ports.length ? detail.ports.join(', ') : 'none found'} mono />
              {detail.live && <Row k="Live" v={detail.live.slice(0, 40)} />}
              <Row k="Findings" v={`${detail.mentions} mention this host`} />
            </dl>
          </div>
        )}
      </div>

      <p className="mt-2 text-[11.5px] leading-relaxed text-ink-faint">
        Node fill shows role: apex domain in lime, subdomains in mint. The badge counts
        findings whose text mentions that host. Findings carry no host field, so this is a
        text match, not an exact attribution.
      </p>
    </section>
  )
}

function Head({ id, count }: { id: string; count: number }) {
  return (
    <div className="mb-2.5 flex items-center gap-3">
      <h3 id={id} className="signage text-[10px] text-accent">
        Recon / Topology
      </h3>
      <span className="h-px flex-1 bg-line" />
      <span className="tnum font-mono text-[10.5px] text-ink-faint">
        {count} host{count === 1 ? '' : 's'}
      </span>
    </div>
  )
}

function Row({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="flex gap-2">
      <dt className="shrink-0 text-ink-faint">{k}</dt>
      <dd className={`min-w-0 break-all text-ink ${mono ? 'font-mono' : ''}`}>{v}</dd>
    </div>
  )
}

function NodeBadge({ role }: { role: 'apex' | 'subdomain' }) {
  return (
    <span
      className="relative flex h-10 w-10 items-center justify-center rounded-full border-2 border-border"
      style={{
        background: role === 'apex' ? 'var(--color-lime)' : 'var(--color-mint)',
        boxShadow: '3px 3px 0 var(--color-ink)',
      }}
    />
  )
}
