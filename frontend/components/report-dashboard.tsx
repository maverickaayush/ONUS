'use client'

import { useEffect, useMemo, useState } from 'react'
import {
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip as ChartTooltip,
  XAxis,
  YAxis,
} from 'recharts'
import {
  ChevronDown,
  Download,
  ExternalLink,
  Info,
  Sparkles,
  TriangleAlert,
  X,
} from 'lucide-react'
import {
  ApiError,
  getFindings,
  getScanStatus,
  reportPdfUrl,
  type ApiFinding,
  type Severity,
} from '@/lib/api'
import {
  SEVERITY,
  SEVERITY_ORDER,
  cn,
  cvssColor,
  normalizeSeverity,
  splitRemediation,
} from '@/lib/format'
import { trackEvent } from '@/lib/analytics'
import {
  ConfidenceTag,
  InfoPopover,
  OnusMark,
  Panel,
  RiskScoreRing,
  ScrambleText,
  SchematicCorners,
  SeverityBadge,
  Tooltip,
  useCountUp,
  usePrefersReducedMotion,
} from './ui'

import { ReconTopology } from './recon-topology'
import { DecorDefs, Motif } from './decor'

interface UiFinding {
  id: number
  title: string
  severity: Severity
  cvss: number
  cvssVector?: string
  owasp: string
  module: string
  priority: number
  description: string
  evidence: string
  cve?: string
  remediation: string[]
  confidence?: string
  verificationNote?: string
}

function mapFinding(f: ApiFinding, i: number): UiFinding {
  return {
    id: i,
    title: f.title,
    severity: normalizeSeverity(f.severity),
    cvss: typeof f.cvss_score === 'number' ? f.cvss_score : 0,
    cvssVector: f.cvss_vector || undefined,
    owasp: f.owasp_category || '-',
    module: f.module,
    priority: typeof f.priority === 'number' ? f.priority : 5,
    description: f.description || f.title,
    evidence: f.evidence || '',
    cve: f.cve_reference || undefined,
    remediation: splitRemediation(f.remediation),
    confidence: f.confidence,
    verificationNote: f.verification_note,
  }
}

type SortKey = 'severity' | 'cvss' | 'priority' | 'title'

export function ReportDashboard({ jobId }: { jobId: string }) {
  const [loading, setLoading] = useState(true)
  const [failed, setFailed] = useState(false)
  const [domain, setDomain] = useState<string>('')
  const [data, setData] = useState<{
    summary: string
    risk: number
    counts: Record<Severity, number>
    findings: UiFinding[]
  } | null>(null)

  // Table controls (all client-side)
  const [sevFilter, setSevFilter] = useState<'All' | Severity>('All')
  // Set by clicking a node in the topology. Matched against title+evidence
  // because findings carry no host field - see recon-topology.tsx.
  const [hostFilter, setHostFilter] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [sortKey, setSortKey] = useState<SortKey>('priority')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')
  const [expanded, setExpanded] = useState<number | null>(null)

  async function load() {
    setLoading(true)
    setFailed(false)
    try {
      const res = await getFindings(jobId)
      setData({
        summary: res.executive_summary || '',
        risk: res.risk_score ?? 0,
        counts: {
          Critical: res.total_critical ?? 0,
          High: res.total_high ?? 0,
          Medium: res.total_medium ?? 0,
          Low: res.total_low ?? 0,
          Informational: res.total_informational ?? 0,
        },
        findings: (res.findings ?? []).map(mapFinding),
      })
      // TODO(analytics): `report_generated` is fundamentally a BACKEND event
      // (the PDF is rendered server-side in reports/generator.py). The frontend
      // only ever *views* an already-generated report, so firing it here would
      // conflate "generated" with "viewed" and double-count on reloads. Emit it
      // from the backend when the PDF is first written, or add a dedicated
      // "report_ready" transition to the status payload and fire it there once.
    } catch (err) {
      // 202 (not ready yet) and genuine errors render identically, by design.
      void (err instanceof ApiError)
      setFailed(true)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
    // Label only - a single non-polling fetch to name the target in the header.
    getScanStatus(jobId)
      .then((s) => setDomain(s.domain))
      .catch(() => setDomain(''))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jobId])

  const filtered = useMemo(() => {
    if (!data) return []
    const q = search.trim().toLowerCase()
    const rows = data.findings.filter(
      (f) =>
        (sevFilter === 'All' || f.severity === sevFilter) &&
        (q === '' || f.title.toLowerCase().includes(q)) &&
        (hostFilter === null ||
          `${f.title} ${f.evidence}`.toLowerCase().includes(hostFilter.toLowerCase())),
    )
    const dir = sortDir === 'asc' ? 1 : -1
    return [...rows].sort((a, b) => {
      let c = 0
      if (sortKey === 'severity') c = SEVERITY[a.severity].order - SEVERITY[b.severity].order
      else if (sortKey === 'cvss') c = a.cvss - b.cvss
      else if (sortKey === 'priority') c = a.priority - b.priority
      else c = a.title.localeCompare(b.title)
      return c * dir
    })
  }, [data, sevFilter, search, sortKey, sortDir, hostFilter])

  function toggleSort(k: SortKey) {
    if (sortKey === k) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    else {
      setSortKey(k)
      setSortDir(k === 'title' ? 'asc' : k === 'priority' ? 'asc' : 'desc')
    }
  }

  return (
    <div>
      {/* Sticky header */}
      <div className="sticky top-0 z-20 border-b border-line bg-canvas/85 backdrop-blur">
        <div className="mx-auto flex max-w-[1080px] items-center justify-between gap-4 px-6 py-4">
          <div className="min-w-0">
            <p className="text-[10px] uppercase tracking-[0.24em] text-ink-faint">Report</p>
            {/* truncate + min-w-0: a long unbroken domain (mono, no spaces) would
                otherwise wrap to many lines and shove the sticky Download button.
                Tooltip surfaces the full value, keyboard- and SR-accessible. */}
            <Tooltip label={domain || jobId}>
              <h1 className="truncate font-mono text-[18px] font-semibold text-ink">{domain || jobId}</h1>
            </Tooltip>
          </div>
          <a
            href={reportPdfUrl(jobId)}
            download
            onClick={() => trackEvent('report_downloaded')}
            className="flex shrink-0 items-center gap-2 rounded-md bg-accent px-4 py-2.5 text-[13px] font-semibold text-white hover:bg-accent/90"
          >
            <Download className="h-4 w-4" strokeWidth={1.8} />
            Download PDF
          </a>
        </div>
      </div>

      <div className="relative w-full overflow-x-clip">
      <DecorDefs />
      {/* Single motif: the topology below is already the page's visual anchor,
          so a second piece here would compete with it rather than frame it. */}
      <Motif kind="magnifier" tone="ink" rotate={-9} opacity={0.07}
        className="left-[2%] top-[26%] hidden h-[250px] w-[250px] 2xl:block" />
      <div className="mx-auto max-w-[1080px] px-6 py-8">
        {failed ? (
          <Panel className="flex flex-col items-center gap-4 p-10 text-center">
            <TriangleAlert className="h-7 w-7 text-high" strokeWidth={1.6} />
            <p className="max-w-[420px] text-[13.5px] leading-relaxed text-ink-dim">
              Failed to load findings. The scan may still be processing.
            </p>
            <button
              onClick={load}
              className="rounded-md bg-accent px-4 py-2 text-[13px] font-semibold text-white hover:bg-accent/90"
            >
              Retry
            </button>
          </Panel>
        ) : (
          <>
            {/* Top: risk ring + stat cards + chart */}
            <div className="grid gap-5 lg:grid-cols-[280px_1fr]">
              <Panel className="relative flex items-center justify-center p-6 onus-fade-up">
                <SchematicCorners />
                {loading || !data ? <RingSkeleton /> : <RiskScoreRing score={data.risk} />}
              </Panel>

              <div className="grid gap-5">
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
                  {SEVERITY_ORDER.map((sev, i) =>
                    loading || !data ? (
                      <CardSkeleton key={sev} />
                    ) : (
                      <StatCard key={sev} severity={sev} count={data.counts[sev]} delay={i * 40} />
                    ),
                  )}
                </div>
                <Panel className="p-4 onus-fade-up" style={{ animationDelay: '120ms' }}>
                  <p className="mb-3 text-[11px] uppercase tracking-[0.18em] text-ink-faint">Severity distribution</p>
                  <SeverityChart counts={data?.counts} />
                </Panel>
              </div>
            </div>

            {/* Executive summary - the "written" typography treatment */}
            <div className="mt-5 onus-fade-up" style={{ animationDelay: '160ms' }}>
              <Panel className="p-6">
                <span className="mb-3 inline-flex items-center gap-1.5 rounded-full border border-accent/30 bg-gradient-to-r from-accent/15 to-[#8b5cf6]/15 px-2.5 py-1 text-[10.5px] font-medium text-accent-soft">
                  <Sparkles className="h-3 w-3" strokeWidth={1.8} />
                  AI-generated narrative
                </span>
                {loading || !data ? (
                  <div className="space-y-2.5">
                    <div className="h-3.5 w-full animate-pulse rounded bg-raised-2" />
                    <div className="h-3.5 w-[92%] animate-pulse rounded bg-raised-2" />
                    <div className="h-3.5 w-[78%] animate-pulse rounded bg-raised-2" />
                  </div>
                ) : (
                  <p className="max-w-[80ch] text-[15px] leading-[1.7] text-ink-dim">{data.summary || 'No summary available.'}</p>
                )}
              </Panel>
            </div>

            {/* RECON // TOPOLOGY - the discovered subdomains rendered as a static
                command-center node graph, built from the REAL recon result set
                (parsed from the findings the API already returns). Revealed all
                at once with a single staggered entrance - never animated as a
                live discovery process, so nothing is shown that wasn't found. */}
            {data && (
              <ReconTopology
                findings={data.findings}
                domain={domain || jobId}
                selectedHost={hostFilter}
                onSelectHost={setHostFilter}
              />
            )}

            {/* Findings - a genuinely clean scan (zero findings, not a filtered
                empty) gets the emblem-anchored all-clear moment (signature
                placement, 4 of 4) instead of an empty table. While loading, a
                calm text placeholder (brief: skeletons only for cards/summary). */}
            {loading || !data ? (
              <div className="mt-8">
                <Panel className="px-6 py-16 text-center text-[13px] text-ink-faint">
                  Loading findings…
                </Panel>
              </div>
            ) : data.findings.length === 0 ? (
              <div className="mt-8">
                <Panel className="flex flex-col items-center gap-4 px-6 py-16 text-center onus-fade-up">
                  <OnusMark className="h-12 w-12 text-accent/70" />
                  <div>
                    <p className="text-[15px] font-semibold text-ink">No issues identified</p>
                    <p className="mx-auto mt-1.5 max-w-[360px] text-[13px] leading-relaxed text-ink-dim">
                      Every module completed and returned no findings. The evidence is clean.
                    </p>
                  </div>
                </Panel>
              </div>
            ) : (
            <div className="mt-8">
              <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                <div className="flex flex-wrap items-center gap-2.5">
                  <h2 className="text-[15px] font-semibold text-ink">
                    Findings <span className="tnum font-mono text-ink-faint">({data?.findings.length ?? 0})</span>
                  </h2>
                  {hostFilter && (
                    <button
                      type="button"
                      onClick={() => setHostFilter(null)}
                      className="inline-flex items-center gap-1.5 rounded-full border-2 border-border bg-mint px-3 py-1 font-mono text-[11.5px] font-semibold text-ink"
                      style={{ boxShadow: 'var(--shadow-hard)' }}
                    >
                      host: {hostFilter}
                      <X className="h-3.5 w-3.5" strokeWidth={2.6} />
                      <span className="sr-only">Clear host filter</span>
                    </button>
                  )}
                </div>
                <div className="flex w-full gap-2 sm:w-auto">
                  <select
                    value={sevFilter}
                    onChange={(e) => setSevFilter(e.target.value as 'All' | Severity)}
                    className="shrink-0 rounded-md border border-line bg-panel px-3 py-2 text-[12.5px] text-ink focus:border-accent/60 focus:outline-none"
                    aria-label="Filter by severity"
                  >
                    <option value="All">All severities</option>
                    {SEVERITY_ORDER.map((s) => (
                      <option key={s} value={s}>
                        {s}
                      </option>
                    ))}
                  </select>
                  <input
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="Search titles…"
                    className="min-w-0 flex-1 rounded-md border border-line bg-panel px-3 py-2 text-[12.5px] text-ink placeholder:text-ink-faint focus:border-accent/60 focus:outline-none sm:w-[200px] sm:flex-none"
                    aria-label="Search findings by title"
                  />
                </div>
              </div>

              <Panel className="overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[720px] border-collapse text-left">
                    <thead>
                      <tr className="border-b border-line text-[10.5px] uppercase tracking-[0.1em] text-ink-faint">
                        <SortTh label="Severity" k="severity" sortKey={sortKey} sortDir={sortDir} onSort={toggleSort} />
                        <SortTh label="Title" k="title" sortKey={sortKey} sortDir={sortDir} onSort={toggleSort} className="w-full" />
                        <SortTh label="CVSS" k="cvss" sortKey={sortKey} sortDir={sortDir} onSort={toggleSort} />
                        <th className="whitespace-nowrap px-4 py-2.5 font-medium">OWASP</th>
                        <th className="whitespace-nowrap px-4 py-2.5 font-medium">Module</th>
                        <SortTh label="Priority" k="priority" sortKey={sortKey} sortDir={sortDir} onSort={toggleSort} />
                      </tr>
                    </thead>
                    <tbody>
                      {filtered.length === 0 && (
                        <tr>
                          <td colSpan={6} className="px-4 py-10 text-center text-[13px] text-ink-faint">
                            No findings match your filters.
                          </td>
                        </tr>
                      )}
                      {filtered.map((f) => (
                        <FindingRow
                          key={f.id}
                          f={f}
                          open={expanded === f.id}
                          onToggle={() => setExpanded((e) => (e === f.id ? null : f.id))}
                        />
                      ))}
                    </tbody>
                  </table>
                </div>
              </Panel>
            </div>
            )}
          </>
        )}
      </div>
      </div>
    </div>
  )
}

function StatCard({ severity, count, delay }: { severity: Severity; count: number; delay: number }) {
  const meta = SEVERITY[severity]
  const reduced = usePrefersReducedMotion()
  const animated = useCountUp(count, 900)
  const shown = reduced ? count : Math.round(animated)
  return (
    <div
      className="relative overflow-hidden rounded-lg border border-line bg-panel p-3.5 onus-fade-up"
      style={{ animationDelay: `${delay}ms` }}
    >
      <div className="absolute inset-x-0 top-0 h-[2px]" style={{ backgroundColor: meta.varName }} />
      <p className="tnum font-mono text-[28px] font-semibold leading-none" style={{ color: meta.varName }}>
        {shown}
      </p>
      <p className="mt-2 text-[11px] font-medium text-ink-dim">{meta.label}</p>
    </div>
  )
}

function SeverityChart({ counts }: { counts?: Record<Severity, number> }) {
  const data = SEVERITY_ORDER.map((s) => ({
    name: SEVERITY[s].short,
    sev: s,
    value: counts ? counts[s] : 0,
    color: SEVERITY[s].varName,
  }))
  return (
    <div className="h-[180px] w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 6, right: 6, left: 0, bottom: 0 }}>
          <defs>
            {SEVERITY_ORDER.map((s) => (
              <linearGradient key={s} id={`grad-${s}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={SEVERITY[s].varName} stopOpacity={0.95} />
                <stop offset="100%" stopColor={SEVERITY[s].varName} stopOpacity={0.45} />
              </linearGradient>
            ))}
          </defs>
          <XAxis
            dataKey="name"
            axisLine={false}
            tickLine={false}
            tick={{ fill: 'var(--color-ink-faint)', fontSize: 11 }}
          />
          <YAxis
            allowDecimals={false}
            axisLine={false}
            tickLine={false}
            tick={{ fill: 'var(--color-ink-faint)', fontSize: 11 }}
            width={44}
          />
          <ChartTooltip
            cursor={{ fill: 'rgba(255,255,255,0.03)' }}
            content={({ active, payload }) => {
              if (!active || !payload || !payload.length) return null
              const p = payload[0].payload as { sev: Severity; value: number }
              return (
                <div className="rounded-md border border-line-strong bg-raised px-3 py-2 text-[12px]">
                  <span className="font-medium" style={{ color: SEVERITY[p.sev].varName }}>
                    {p.sev}
                  </span>
                  <span className="ml-2 text-ink-dim">
                    {p.value} finding{p.value === 1 ? '' : 's'}
                  </span>
                </div>
              )
            }}
          />
          <Bar dataKey="value" radius={[3, 3, 0, 0]} animationDuration={900}>
            {data.map((d) => (
              <Cell key={d.sev} fill={`url(#grad-${d.sev})`} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

function SortTh({
  label,
  k,
  sortKey,
  sortDir,
  onSort,
  className,
}: {
  label: string
  k: SortKey
  sortKey: SortKey
  sortDir: 'asc' | 'desc'
  onSort: (k: SortKey) => void
  className?: string
}) {
  const active = sortKey === k
  return (
    <th className={cn('whitespace-nowrap px-4 py-2.5 font-medium', className)}>
      <button onClick={() => onSort(k)} className={cn('inline-flex items-center gap-1', active ? 'text-ink' : 'hover:text-ink-dim')}>
        {label}
        <span className="text-[9px]">{active ? (sortDir === 'asc' ? '▲' : '▼') : '↕'}</span>
      </button>
    </th>
  )
}

function FindingRow({ f, open, onToggle }: { f: UiFinding; open: boolean; onToggle: () => void }) {
  return (
    <>
      <tr
        role="button"
        tabIndex={0}
        aria-expanded={open}
        onClick={onToggle}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault()
            onToggle()
          }
        }}
        className={cn('cursor-pointer border-b border-line/60 transition-colors hover:bg-white/[0.02]', open && 'bg-white/[0.02]')}
      >
        <td className="px-4 py-3 align-top">
          <div className="flex flex-col items-start gap-1.5">
            <SeverityBadge severity={f.severity} size="xs" />
            <ConfidenceTag confidence={f.confidence} />
          </div>
        </td>
        <td className="px-4 py-3">
          <span className="flex items-center gap-2 text-[13px] text-ink">
            <ChevronDown className={cn('h-3.5 w-3.5 shrink-0 text-ink-faint transition-transform', open && 'rotate-180')} strokeWidth={1.8} />
            <ScrambleText value={f.title} duration={300} />
          </span>
        </td>
        <td className="whitespace-nowrap px-4 py-3">
          <span className="tnum font-mono text-[13px] font-medium" style={{ color: cvssColor(f.cvss) }}>
            {f.cvss.toFixed(1)}
          </span>
        </td>
        <td className="whitespace-nowrap px-4 py-3 text-[12px] text-ink-dim">{f.owasp}</td>
        <td className="whitespace-nowrap px-4 py-3">
          <span className="rounded-xs border border-line bg-raised px-2 py-0.5 font-mono text-[11px] text-ink-dim">{f.module}</span>
        </td>
        <td className="whitespace-nowrap px-4 py-3 tnum font-mono text-[13px] text-ink-dim">{f.priority}</td>
      </tr>
      {open && (
        <tr className="border-b border-line/60 bg-canvas/40">
          {/* The detail panel breaks out of the table's min-w horizontal scroll
              on narrow viewports: sticky-left + viewport-width so prose reads
              top-to-bottom instead of sideways. Reverts to a normal full-cell
              two-column layout at lg. (112px = 64px rail + the container's px-6.) */}
          <td colSpan={6} className="p-0">
            <div className="sticky left-0 w-[calc(100vw_-_112px)] max-w-[100vw] px-4 py-5 lg:w-auto lg:max-w-none">
            <div className="grid gap-5 lg:grid-cols-2">
              <div>
                <SectionLabel>Description</SectionLabel>
                <p className="mt-1.5 text-[13.5px] leading-relaxed text-ink-dim">{f.description}</p>

                {(f.cve || f.cvssVector) && (
                  <div className="mt-3 flex flex-wrap items-center gap-2">
                    {f.cve && (
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(f.cve)}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1.5 rounded-md border border-line px-2.5 py-1 font-mono text-[11.5px] text-accent-soft hover:border-accent/50"
                      >
                        {f.cve}
                        <ExternalLink className="h-3 w-3" strokeWidth={1.8} />
                      </a>
                    )}
                    {f.cvssVector && (
                      <InfoPopover
                        label="Show CVSS v3.1 vector"
                        trigger={
                          <span className="inline-flex items-center gap-1.5 rounded-md border border-line px-2.5 py-1 font-mono text-[11.5px] text-ink-dim transition-colors hover:border-line-strong hover:text-ink">
                            CVSS vector
                            <Info className="h-3 w-3" strokeWidth={1.8} />
                          </span>
                        }
                      >
                        <p className="mb-1.5 text-[9.5px] font-medium uppercase tracking-[0.16em] text-ink-faint">
                          CVSS v3.1 base vector
                        </p>
                        <code className="block break-all font-mono text-[11.5px] leading-relaxed text-[var(--color-cyan)]">
                          {f.cvssVector}
                        </code>
                      </InfoPopover>
                    )}
                  </div>
                )}

                {f.verificationNote && (
                  <div className="mt-4">
                    <SectionLabel>Verification note</SectionLabel>
                    <p className="mt-1.5 text-[13.5px] leading-relaxed text-ink-dim">{f.verificationNote}</p>
                  </div>
                )}
              </div>

              <div>
                <SectionLabel>Evidence</SectionLabel>
                <pre className="mt-1.5 max-h-[200px] overflow-auto rounded-md border border-line bg-[#07080a] p-3 font-mono text-[11.5px] leading-relaxed text-[var(--color-cyan)]">
                  {f.evidence || '(no evidence captured)'}
                </pre>

                <div className="mt-4">
                  <SectionLabel>Remediation</SectionLabel>
                  <ol className="mt-1.5 space-y-1.5">
                    {f.remediation.map((step, i) => (
                      <li key={i} className="flex gap-2.5 text-[13px] leading-relaxed text-ink-dim">
                        <span className="tnum mt-[1px] font-mono text-[11px] text-accent-soft">{String(i + 1).padStart(2, '0')}</span>
                        <span>{step}</span>
                      </li>
                    ))}
                  </ol>
                </div>
              </div>
            </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return <p className="text-[10.5px] font-medium uppercase tracking-[0.16em] text-ink-faint">{children}</p>
}

function CardSkeleton() {
  return <div className="h-[84px] animate-pulse rounded-lg border border-line bg-panel" />
}
function RingSkeleton() {
  return <div className="h-[188px] w-[188px] animate-pulse rounded-full border-[9px] border-raised-2" />
}
