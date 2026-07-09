"use client"

import { useState, useMemo, useEffect } from "react"
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts"
import {
  SeverityBadge,
  ModuleChip,
  ConfidenceTag,
  RiskScoreRing,
  SEVERITY_CONFIG,
  SummaryCard,
  type Severity,
} from "@/components/vapt/shared"
import { VaptBackground } from "@/components/vapt/background"

// Finding shape used by the UI (maps from API fields in ReportDashboard)
export interface Finding {
  id: number
  title: string
  severity: Severity
  cvss: number
  owasp: string
  module: string
  priority: number
  description: string
  evidence: string
  confidence?: string | null
  verificationNote?: string | null
  cve?: string
  remediation: string[]
}
import { cn } from "@/lib/utils"
import { getFindings, reportPdfUrl } from "@/lib/api"
import type { FindingsResponse } from "@/lib/api"

// SummaryCard (glowing count-up card) now lives in shared.tsx - generalized
// to accept plain color props so both this dashboard and the Scans page can
// use the same component instead of duplicating it.

// ─── Chart data (built from live counts) ─────────────────────────────────────
function buildChartData(counts: Record<Severity, number>) {
  return (["Critical", "High", "Medium", "Low", "Informational"] as Severity[]).map(
    (sev) => ({
      name: sev === "Informational" ? "Info" : sev,
      count: counts[sev] ?? 0,
      fill: SEVERITY_CONFIG[sev].hex,
    }),
  )
}

function ChartTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean
  payload?: Array<{ value: number }>
  label?: string
}) {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded-lg border border-white/10 bg-[#141c35] px-3 py-2 text-xs shadow-xl">
      <p className="font-medium text-slate-200">{label}</p>
      <p className="text-slate-400">
        {payload[0].value} {payload[0].value === 1 ? "finding" : "findings"}
      </p>
    </div>
  )
}

// ─── Expandable Finding Row ───────────────────────────────────────────────────
function FindingRow({
  finding,
  index,
}: {
  finding: Finding
  index: number
}) {
  const [open, setOpen] = useState(false)

  return (
    <>
      <tr
        className={cn(
          "cursor-pointer border-b border-white/5 transition-all duration-200 hover:bg-white/5",
          open && "bg-white/5",
        )}
        onClick={() => setOpen((o) => !o)}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => e.key === "Enter" && setOpen((o) => !o)}
        aria-expanded={open}
      >
        <td className="px-4 py-3 whitespace-nowrap">
          <div className="flex items-center gap-1.5 flex-wrap">
            <SeverityBadge severity={finding.severity} size="xs" />
            <ConfidenceTag confidence={finding.confidence} />
          </div>
        </td>
        <td className="px-4 py-3">
          <span className="text-sm font-medium text-slate-200 flex items-center gap-1.5">
            <svg
              className={cn(
                "h-3 w-3 text-slate-500 flex-shrink-0 transition-transform",
                open && "rotate-90",
              )}
              viewBox="0 0 20 20"
              fill="currentColor"
              aria-hidden="true"
            >
              <path
                fillRule="evenodd"
                d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z"
                clipRule="evenodd"
              />
            </svg>
            {finding.title}
          </span>
        </td>
        <td className="px-4 py-3 whitespace-nowrap">
          <span
            className={cn(
              "text-sm font-semibold",
              finding.cvss >= 7
                ? "text-red-400"
                : finding.cvss >= 4
                  ? "text-amber-400"
                  : "text-slate-400",
            )}
          >
            {finding.cvss.toFixed(1)}
          </span>
        </td>
        <td className="px-4 py-3 whitespace-nowrap text-xs text-slate-500 font-mono">
          {finding.owasp}
        </td>
        <td className="px-4 py-3 whitespace-nowrap">
          <ModuleChip module={finding.module} />
        </td>
        <td className="px-4 py-3 whitespace-nowrap">
          <span className="inline-flex items-center justify-center h-6 w-6 rounded-full bg-white/5 border border-white/10 text-slate-300 text-xs font-bold">
            {finding.priority}
          </span>
        </td>
      </tr>

      {/* Expanded detail row */}
      <tr className="border-b border-white/5">
        <td colSpan={6} className="p-0">
          <div
            className={cn(
              "grid transition-all duration-200 ease-out",
              open ? "grid-rows-[1fr]" : "grid-rows-[0fr]",
            )}
          >
            <div className="overflow-hidden">
              <div className="mx-4 my-4 border border-white/8 rounded-xl overflow-hidden backdrop-blur-sm bg-white/[0.03]">
                {/* Description */}
                <div className="px-5 py-4 border-b border-white/8">
                  <h4 className="text-[11px] font-medium text-slate-500 uppercase tracking-wide mb-2">
                    Description
                  </h4>
                  <p className="text-sm text-slate-300 leading-relaxed">
                    {finding.description}
                  </p>
                </div>

                {/* Evidence */}
                <div className="px-5 py-4 border-b border-white/8">
                  <h4 className="text-[11px] font-medium text-slate-500 uppercase tracking-wide mb-2">
                    Evidence
                  </h4>
                  <pre className="text-xs font-mono bg-black/40 text-emerald-400 rounded-xl p-4 overflow-x-auto max-h-[200px] leading-relaxed border border-emerald-500/20">
                    {finding.evidence}
                  </pre>
                </div>

                {/* Verification - only rendered when the confidence-verification
                    stage actually left a note on this finding (confirmed or
                    unverified; 'probable' findings were never re-checked and
                    carry no note, matching the PDF report's convention). */}
                {finding.verificationNote && (
                  <div className="px-5 py-4 border-b border-white/8">
                    <h4 className="text-[11px] font-medium text-slate-500 uppercase tracking-wide mb-2 flex items-center gap-2">
                      Verification
                      <ConfidenceTag confidence={finding.confidence} />
                    </h4>
                    <p className="text-sm text-slate-300 leading-relaxed">
                      {finding.verificationNote}
                    </p>
                  </div>
                )}

                {/* CVE / CWE reference */}
                {finding.cve && (
                  <div className="px-5 py-4 border-b border-white/8">
                    <h4 className="text-[11px] font-medium text-slate-500 uppercase tracking-wide mb-2">
                      Reference
                    </h4>
                    <a
                      href={`https://cwe.mitre.org/data/definitions/${finding.cve.replace("CWE-", "")}.html`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-sm text-blue-400 hover:text-blue-300 hover:underline font-medium"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {finding.cve} — MITRE CWE
                    </a>
                  </div>
                )}

                {/* Remediation */}
                <div className="px-5 py-4">
                  <h4 className="text-[11px] font-medium text-slate-500 uppercase tracking-wide mb-3">
                    Remediation
                  </h4>
                  <ol className="space-y-2.5">
                    {finding.remediation.map((step, i) => (
                      <li key={i} className="flex items-start gap-3 text-sm text-slate-300">
                        <span className="mt-0.5 flex-shrink-0 inline-flex items-center justify-center h-5 w-5 rounded-full bg-blue-500/15 border border-blue-500/30 text-blue-300 text-[11px] font-bold">
                          {i + 1}
                        </span>
                        <span className="leading-relaxed">{step}</span>
                      </li>
                    ))}
                  </ol>
                </div>
              </div>
            </div>
          </div>
        </td>
      </tr>
    </>
  )
}

// ─── Findings Table ───────────────────────────────────────────────────────────
type SortKey = "severity" | "cvss" | "priority" | "title"
type SortDir = "asc" | "desc"

const SEVERITY_ORDER: Record<Severity, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
  Informational: 4,
}

function FindingsTable({ findings }: { findings: Finding[] }) {
  const [filter, setFilter] = useState<Severity | "All">("All")
  const [search, setSearch] = useState("")
  const [sortKey, setSortKey] = useState<SortKey>("priority")
  const [sortDir, setSortDir] = useState<SortDir>("asc")

  const filtered = useMemo(() => {
    let rows = [...findings]

    if (filter !== "All") {
      rows = rows.filter((f) => f.severity === filter)
    }
    if (search.trim()) {
      const q = search.toLowerCase()
      rows = rows.filter((f) => f.title.toLowerCase().includes(q))
    }

    rows.sort((a, b) => {
      let cmp = 0
      if (sortKey === "severity") cmp = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
      else if (sortKey === "cvss") cmp = a.cvss - b.cvss
      else if (sortKey === "priority") cmp = a.priority - b.priority
      else if (sortKey === "title") cmp = a.title.localeCompare(b.title)
      return sortDir === "asc" ? cmp : -cmp
    })
    return rows
  }, [findings, filter, search, sortKey, sortDir])

  function toggleSort(key: SortKey) {
    if (sortKey === key) setSortDir((d) => (d === "asc" ? "desc" : "asc"))
    else {
      setSortKey(key)
      setSortDir("asc")
    }
  }

  function SortIcon({ col }: { col: SortKey }) {
    if (sortKey !== col) {
      return (
        <svg className="h-3 w-3 text-slate-600 ml-1 inline" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
          <path d="M5 12a1 1 0 102 0V6.414l1.293 1.293a1 1 0 001.414-1.414l-3-3a1 1 0 00-1.414 0l-3 3a1 1 0 001.414 1.414L5 6.414V12zM15 8a1 1 0 10-2 0v5.586l-1.293-1.293a1 1 0 00-1.414 1.414l3 3a1 1 0 001.414 0l3-3a1 1 0 00-1.414-1.414L15 13.586V8z" />
        </svg>
      )
    }
    return sortDir === "asc" ? (
      <svg className="h-3 w-3 text-blue-400 ml-1 inline" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
        <path fillRule="evenodd" d="M14.707 12.707a1 1 0 01-1.414 0L10 9.414l-3.293 3.293a1 1 0 01-1.414-1.414l4-4a1 1 0 011.414 0l4 4a1 1 0 010 1.414z" clipRule="evenodd" />
      </svg>
    ) : (
      <svg className="h-3 w-3 text-blue-400 ml-1 inline" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
        <path fillRule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clipRule="evenodd" />
      </svg>
    )
  }

  const SEVERITIES: Array<Severity | "All"> = ["All", "Critical", "High", "Medium", "Low", "Informational"]

  return (
    <div className="backdrop-blur-sm bg-white/5 rounded-2xl border border-white/8 overflow-hidden">
      {/* Table header controls */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-6 py-4 border-b border-white/8">
        <h2 className="text-base font-bold tracking-tight text-slate-100">Findings</h2>
        <div className="flex flex-wrap items-center gap-2">
          {/* Filter */}
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value as Severity | "All")}
            className="text-sm border border-white/10 rounded-lg px-3 py-1.5 text-slate-200 bg-white/5 focus:outline-none focus:ring-2 focus:ring-blue-500/50 [&>option]:bg-[#141c35]"
            aria-label="Filter by severity"
          >
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s === "All" ? "All Severities" : s}
              </option>
            ))}
          </select>

          {/* Search */}
          <div className="relative">
            <svg
              className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500"
              viewBox="0 0 20 20"
              fill="currentColor"
              aria-hidden="true"
            >
              <path fillRule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clipRule="evenodd" />
            </svg>
            <input
              type="text"
              placeholder="Search findings..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-8 pr-3 py-1.5 text-sm border border-white/10 rounded-lg text-slate-200 placeholder:text-slate-600 bg-white/5 focus:outline-none focus:ring-2 focus:ring-blue-500/50 w-44"
              aria-label="Search findings"
            />
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left" aria-label="Security findings">
          <thead className="bg-white/5 border-b border-white/8">
            <tr>
              {[
                { label: "Severity", key: "severity" as SortKey, w: "w-32" },
                { label: "Title", key: "title" as SortKey, w: "" },
                { label: "CVSS", key: "cvss" as SortKey, w: "w-20" },
                { label: "OWASP", key: null, w: "w-28" },
                { label: "Module", key: null, w: "w-28" },
                { label: "Priority", key: "priority" as SortKey, w: "w-20" },
              ].map(({ label, key, w }) => (
                <th
                  key={label}
                  className={cn(
                    "px-4 py-3 text-[11px] font-medium text-slate-500 uppercase tracking-widest",
                    w,
                    key && "cursor-pointer select-none hover:text-slate-300",
                  )}
                  onClick={() => key && toggleSort(key)}
                  scope="col"
                >
                  {label}
                  {key && <SortIcon col={key} />}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-6 py-10 text-center text-sm text-slate-500">
                  No findings match your filters.
                </td>
              </tr>
            ) : (
              filtered.map((finding, i) => (
                <FindingRow key={finding.id} finding={finding} index={i} />
              ))
            )}
          </tbody>
        </table>
      </div>
      <div className="px-6 py-3 border-t border-white/8 text-xs text-slate-500">
        Showing {filtered.length} of {findings.length} findings
      </div>
    </div>
  )
}

// ─── Skeleton loader ──────────────────────────────────────────────────────────
function SkeletonCard() {
  return (
    <div className="rounded-2xl border border-white/8 bg-white/5 p-4 animate-pulse">
      <div className="h-8 w-12 bg-white/10 rounded-lg mx-auto mb-2" />
      <div className="h-3 w-16 bg-white/5 rounded mx-auto" />
    </div>
  )
}

// ─── Main Report Dashboard ────────────────────────────────────────────────────
export function ReportDashboard({ jobId }: { jobId: string }) {
  const [data, setData] = useState<FindingsResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState("")

  async function load() {
    setLoading(true)
    setFetchError("")
    try {
      const res = await getFindings(jobId)
      setData(res)
    } catch {
      setFetchError("Failed to load findings. The scan may still be processing.")
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [jobId]) // eslint-disable-line react-hooks/exhaustive-deps

  // Map API findings to internal Finding shape
  const findings: Finding[] = useMemo(() => {
    if (!data) return []
    let _id = 0
    return data.findings.map((f) => ({
      id: ++_id,
      title: f.title,
      severity: (f.severity as Severity) ?? "Informational",
      cvss: f.cvss_score ?? 0,
      owasp: f.owasp_category ?? "-",
      module: f.module,
      priority: f.priority ?? 5,
      description: f.description ?? f.title,
      evidence: f.evidence,
      confidence: f.confidence ?? null,
      verificationNote: f.verification_note ?? null,
      cve: f.cve_reference ?? undefined,
      remediation: Array.isArray(f.remediation)
        ? (f.remediation as string[])
        : typeof f.remediation === "string"
          ? f.remediation.split("\n").filter(Boolean)
          : ["Review and remediate this finding per security best practices."],
    }))
  }, [data])

  const counts: Record<Severity, number> = {
    Critical:      data?.total_critical      ?? 0,
    High:          data?.total_high          ?? 0,
    Medium:        data?.total_medium        ?? 0,
    Low:           data?.total_low           ?? 0,
    Informational: data?.total_informational ?? 0,
  }

  const chartData = buildChartData(counts)
  const riskScore = data?.risk_score ?? 0
  const executiveSummary = data?.executive_summary ?? ""

  return (
    <div className="vapt-noise relative min-h-[calc(100vh-56px)] overflow-hidden">
      <VaptBackground />

      {/* Sticky report header */}
      <div className="sticky top-14 z-30 backdrop-blur-md bg-[#0a0e1a]/80 border-b border-white/8">
        <div className="max-w-6xl mx-auto px-4 py-3 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-lg font-bold tracking-tight text-slate-100">
              {data ? (data as unknown as { domain?: string }).domain || "VAPT Report" : "Loading..."}
            </h1>
            <p className="text-xs text-slate-500">Security Assessment Report</p>
          </div>
          <a
            href={reportPdfUrl(jobId)}
            download
            className="inline-flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-blue-600 to-blue-500 text-white text-sm font-semibold rounded-xl shadow-lg shadow-blue-500/25 hover:shadow-blue-500/40 hover:brightness-110 transition-all"
            aria-label="Download PDF report"
          >
            <svg className="h-4 w-4" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
              <path fillRule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm3.293-7.707a1 1 0 011.414 0L9 10.586V3a1 1 0 112 0v7.586l1.293-1.293a1 1 0 111.414 1.414l-3 3a1 1 0 01-1.414 0l-3-3a1 1 0 010-1.414z" clipRule="evenodd" />
            </svg>
            Download PDF
          </a>
        </div>
      </div>

      <main className="relative z-10 max-w-6xl mx-auto py-8 px-4 space-y-6">
        {/* Error state */}
        {fetchError && (
          <div className="backdrop-blur-sm bg-red-500/10 border border-red-500/20 rounded-2xl p-6 flex items-center justify-between gap-4">
            <p className="text-sm text-red-300">{fetchError}</p>
            <button
              onClick={load}
              className="px-4 py-2 rounded-xl bg-white/5 border border-white/10 text-slate-300 text-sm hover:bg-white/10 transition-colors"
            >
              Retry
            </button>
          </div>
        )}

        {/* Risk score hero + summary cards */}
        <div className="grid grid-cols-1 lg:grid-cols-[300px_1fr] gap-6 items-center">
          <div className="backdrop-blur-sm bg-white/5 border border-white/8 rounded-2xl p-8 flex items-center justify-center">
            <RiskScoreRing score={riskScore} />
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
            {loading
              ? Array.from({ length: 5 }).map((_, i) => <SkeletonCard key={i} />)
              : (["Critical", "High", "Medium", "Low", "Informational"] as Severity[]).map((sev) => (
                  <SummaryCard
                    key={sev}
                    label={sev === "Informational" ? "Info" : sev}
                    count={counts[sev]}
                    hex={SEVERITY_CONFIG[sev].hex}
                    glow={SEVERITY_CONFIG[sev].glow}
                    textClass={SEVERITY_CONFIG[sev].text}
                  />
                ))}
          </div>
        </div>

        {/* Chart + Executive Summary */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Bar chart */}
          <div className="backdrop-blur-sm bg-white/5 border border-white/8 rounded-2xl p-6">
            <h2 className="text-xs font-medium uppercase tracking-wide text-slate-400 mb-4">
              Severity Distribution
            </h2>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={chartData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }} barSize={36}>
                <defs>
                  {chartData.map((entry) => (
                    <linearGradient key={entry.name} id={`grad-${entry.name}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor={entry.fill} stopOpacity={0.95} />
                      <stop offset="100%" stopColor={entry.fill} stopOpacity={0.45} />
                    </linearGradient>
                  ))}
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                <XAxis dataKey="name" tick={{ fontSize: 12, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fontSize: 12, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
                <Tooltip cursor={{ fill: "rgba(255,255,255,0.03)" }} content={<ChartTooltip />} />
                <Bar dataKey="count" radius={[6, 6, 0, 0]} isAnimationActive animationDuration={900}>
                  {chartData.map((entry) => (
                    <Cell key={entry.name} fill={`url(#grad-${entry.name})`} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Executive Summary */}
          <div className="relative backdrop-blur-sm bg-white/5 border border-white/8 border-l-2 border-l-blue-500/60 rounded-2xl p-6">
            <div className="flex items-start justify-between mb-3">
              <h2 className="text-xs font-medium uppercase tracking-wide text-slate-400">Executive Summary</h2>
              <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-gradient-to-r from-blue-500/20 to-violet-500/20 border border-blue-500/30 text-blue-300 text-[10px] font-semibold uppercase tracking-wide">
                <svg className="h-2.5 w-2.5" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                  <path fillRule="evenodd" d="M11.3 1.046A1 1 0 0112 2v5h4a1 1 0 01.82 1.573l-7 10A1 1 0 018 18v-5H4a1 1 0 01-.82-1.573l7-10a1 1 0 011.12-.38z" clipRule="evenodd" />
                </svg>
                AI Analysis
              </span>
            </div>
            {loading ? (
              <div className="space-y-2 animate-pulse">
                <div className="h-3 bg-white/10 rounded w-full" />
                <div className="h-3 bg-white/10 rounded w-5/6" />
                <div className="h-3 bg-white/10 rounded w-4/6" />
              </div>
            ) : (
              <p className="text-sm text-slate-300 leading-relaxed italic">
                &ldquo;{executiveSummary}&rdquo;
              </p>
            )}
          </div>
        </div>

        {/* Findings Table */}
        <FindingsTable findings={findings} />
      </main>
    </div>
  )
}
