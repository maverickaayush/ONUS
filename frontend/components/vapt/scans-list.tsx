"use client"

import { useState, useEffect, useRef, useCallback } from "react"
import { useRouter, usePathname, useSearchParams } from "next/navigation"
import Link from "next/link"
import { StatusChip, ProgressBar, SummaryCard } from "@/components/vapt/shared"
import { VaptBackground } from "@/components/vapt/background"
import { cn } from "@/lib/utils"
import { getScans, getScanModules } from "@/lib/api"
import type { ScanListItem, ScanListCounts, ScanModuleInfo } from "@/lib/api"

type Tab = "all" | "active" | "awaiting_user_decision" | "completed" | "failed"
type SortKey = "created_at" | "updated_at" | "status" | "target"
type SortDir = "asc" | "desc"

const TABS: Array<{ key: Tab; label: string }> = [
  { key: "all", label: "All" },
  { key: "active", label: "Running" },
  { key: "awaiting_user_decision", label: "Awaiting Decision" },
  { key: "completed", label: "Completed" },
  { key: "failed", label: "Failed" },
]

const PAGE_SIZE = 20
const POLL_MS = 12000 // within the requested 10-15s window

function SortIcon({ active, dir }: { active: boolean; dir: SortDir }) {
  if (!active) {
    return (
      <svg className="h-3 w-3 text-slate-600 ml-1 inline" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
        <path d="M5 12a1 1 0 102 0V6.414l1.293 1.293a1 1 0 001.414-1.414l-3-3a1 1 0 00-1.414 0l-3 3a1 1 0 001.414 1.414L5 6.414V12zM15 8a1 1 0 10-2 0v5.586l-1.293-1.293a1 1 0 00-1.414 1.414l3 3a1 1 0 001.414 0l3-3a1 1 0 00-1.414-1.414L15 13.586V8z" />
      </svg>
    )
  }
  return dir === "asc" ? (
    <svg className="h-3 w-3 text-blue-400 ml-1 inline" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
      <path fillRule="evenodd" d="M14.707 12.707a1 1 0 01-1.414 0L10 9.414l-3.293 3.293a1 1 0 01-1.414-1.414l4-4a1 1 0 011.414 0l4 4a1 1 0 010 1.414z" clipRule="evenodd" />
    </svg>
  ) : (
    <svg className="h-3 w-3 text-blue-400 ml-1 inline" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
      <path fillRule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clipRule="evenodd" />
    </svg>
  )
}

const EMPTY_COUNTS: ScanListCounts = { running: 0, awaiting_user_decision: 0, completed: 0, failed: 0, total: 0 }

export function ScansList() {
  const router = useRouter()
  const pathname = usePathname()
  const searchParams = useSearchParams()

  // View state is a pure function of the URL - refresh/back-button/shared
  // links all preserve tab/search/sort/page.
  const tab = (searchParams.get("tab") as Tab) || "all"
  const search = searchParams.get("search") || ""
  const sortKey = (searchParams.get("sort") as SortKey) || "created_at"
  const sortDir = (searchParams.get("order") as SortDir) || "desc"
  const page = Number(searchParams.get("page")) || 1

  const [searchInput, setSearchInput] = useState(search)
  const [scans, setScans] = useState<ScanListItem[]>([])
  const [counts, setCounts] = useState<ScanListCounts>(EMPTY_COUNTS)
  const [totalPages, setTotalPages] = useState(1)
  const [total, setTotal] = useState(0)
  const [moduleDefs, setModuleDefs] = useState<ScanModuleInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    getScanModules().then(setModuleDefs).catch(() => {})
  }, [])

  function updateUrl(next: Partial<{ tab: Tab; search: string; sort: SortKey; order: SortDir; page: number }>) {
    const params = new URLSearchParams(searchParams.toString())
    const merged = { tab, search, sort: sortKey, order: sortDir, page, ...next }
    // Changing tab/search/sort resets to page 1, unless page itself is what changed.
    if (!("page" in next)) merged.page = 1
    Object.entries(merged).forEach(([k, v]) => {
      if (v === "" || v === undefined || (k === "tab" && v === "all") || (k === "page" && v === 1)) {
        params.delete(k)
      } else {
        params.set(k, String(v))
      }
    })
    const qs = params.toString()
    router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false })
  }

  const poll = useCallback(async () => {
    if (document.hidden) return
    try {
      const data = await getScans({
        status: tab === "all" ? undefined : tab,
        search: search || undefined,
        sort: sortKey,
        order: sortDir,
        page,
        page_size: PAGE_SIZE,
      })
      setScans(data.scans)
      setCounts(data.counts)
      setTotal(data.total)
      setTotalPages(data.total_pages)
      setError("")
      setSelectedIds(new Set())

      // Stop scheduling further auto-polls once nothing anywhere is active -
      // no point refreshing a page that can't change. visibilitychange
      // (below) still fires one poll on tab refocus regardless, and the
      // Refresh button lets a user force a check any time.
      const active = data.counts.running > 0 || data.counts.awaiting_user_decision > 0
      if (active) {
        timeoutRef.current = setTimeout(poll, POLL_MS)
      }
    } catch {
      setError("Connection lost - retrying...")
      timeoutRef.current = setTimeout(poll, POLL_MS)
    } finally {
      setLoading(false)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, search, sortKey, sortDir, page])

  useEffect(() => {
    if (timeoutRef.current) clearTimeout(timeoutRef.current)
    poll()

    const onVisibility = () => {
      if (!document.hidden) poll()
    }
    document.addEventListener("visibilitychange", onVisibility)
    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current)
      document.removeEventListener("visibilitychange", onVisibility)
    }
  }, [poll])

  function toggleSort(key: SortKey) {
    if (sortKey === key) updateUrl({ sort: key, order: sortDir === "asc" ? "desc" : "asc" })
    else updateUrl({ sort: key, order: "asc" })
  }

  function submitSearch(e: React.FormEvent) {
    e.preventDefault()
    updateUrl({ search: searchInput })
  }

  const moduleLabel = (id: string | null) => {
    if (!id) return "—"
    if (id === "Analysing") return "Analysing"
    return moduleDefs.find((m) => m.id === id)?.label ?? id
  }

  const allSelected = scans.length > 0 && scans.every((s) => selectedIds.has(s.job_id))
  function toggleSelectAll() {
    setSelectedIds(allSelected ? new Set() : new Set(scans.map((s) => s.job_id)))
  }
  function toggleSelectOne(id: string) {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const columns: Array<{ label: string; key: SortKey | null }> = [
    { label: "Target", key: "target" },
    { label: "Status", key: "status" },
    { label: "Progress", key: null },
    { label: "Current Module", key: null },
    { label: "Risk Score", key: null },
    { label: "Started", key: "created_at" },
    { label: "Last Updated", key: "updated_at" },
    { label: "Actions", key: null },
  ]

  return (
    <main className="vapt-noise relative min-h-[calc(100vh-56px)] py-10 px-4 overflow-hidden">
      <VaptBackground />
      <div className="relative z-10 max-w-7xl mx-auto space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-slate-100">Scans</h1>
            <p className="text-sm text-slate-500 mt-1">Every scan in one place - discovery only, no scan logic lives here.</p>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => poll()}
              className="px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-slate-300 text-sm hover:bg-white/10 transition-colors"
            >
              Refresh
            </button>
            <Link href="/" className="px-3 py-1.5 rounded-lg bg-gradient-to-r from-blue-600 to-blue-500 text-white text-sm font-medium hover:brightness-110 transition-all">
              + New Scan
            </Link>
          </div>
        </div>

        {/* Summary cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <SummaryCard label="Running" count={counts.running} hex="#3B82F6" glow="rgba(59,130,246,0.2)" textClass="text-blue-400" />
          <SummaryCard label="Awaiting Decision" count={counts.awaiting_user_decision} hex="#F59E0B" glow="rgba(245,158,11,0.2)" textClass="text-amber-400" />
          <SummaryCard label="Completed" count={counts.completed} hex="#34D399" glow="rgba(52,211,153,0.2)" textClass="text-emerald-400" />
          <SummaryCard label="Failed" count={counts.failed} hex="#EF4444" glow="rgba(239,68,68,0.2)" textClass="text-red-400" />
        </div>

        <div className="backdrop-blur-sm bg-white/5 rounded-2xl border border-white/8 overflow-hidden">
          {/* Tabs + search */}
          <div className="flex flex-wrap items-center justify-between gap-3 px-6 py-4 border-b border-white/8">
            <div className="flex flex-wrap items-center gap-1.5">
              {TABS.map((t) => (
                <button
                  key={t.key}
                  type="button"
                  onClick={() => updateUrl({ tab: t.key })}
                  className={cn(
                    "px-3 py-1.5 rounded-lg text-sm font-medium transition-all",
                    tab === t.key
                      ? "bg-white/10 text-slate-100 border border-white/10"
                      : "text-slate-400 hover:text-slate-200 hover:bg-white/5",
                  )}
                >
                  {t.label}
                </button>
              ))}
            </div>
            <form onSubmit={submitSearch} className="relative">
              <svg className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                <path fillRule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clipRule="evenodd" />
              </svg>
              <input
                type="text"
                placeholder="Search by target..."
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                className="pl-8 pr-3 py-1.5 text-sm border border-white/10 rounded-lg text-slate-200 placeholder:text-slate-600 bg-white/5 focus:outline-none focus:ring-2 focus:ring-blue-500/50 w-52"
                aria-label="Search by target"
              />
            </form>
          </div>

          {/* Bulk-selection bar - hook point for future bulk actions (e.g.
              bulk cancel/retry). No backend bulk endpoint exists yet, so no
              real action buttons are wired up - just the selection plumbing
              so adding one later doesn't require touching the table. */}
          {selectedIds.size > 0 && (
            <div className="flex items-center justify-between px-6 py-2.5 bg-blue-500/10 border-b border-blue-500/20 text-sm text-blue-300">
              <span>{selectedIds.size} selected</span>
              <button type="button" onClick={() => setSelectedIds(new Set())} className="text-blue-400 hover:text-blue-200">
                Clear
              </button>
            </div>
          )}

          {/* Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left" aria-label="Scans">
              <thead className="bg-white/5 border-b border-white/8">
                <tr>
                  <th className="px-4 py-3 w-10">
                    <input
                      type="checkbox"
                      checked={allSelected}
                      onChange={toggleSelectAll}
                      aria-label="Select all scans on this page"
                      className="h-4 w-4 rounded border-white/20 bg-transparent accent-blue-500"
                    />
                  </th>
                  {columns.map(({ label, key }) => (
                    <th
                      key={label}
                      className={cn(
                        "px-4 py-3 text-[11px] font-medium text-slate-500 uppercase tracking-widest whitespace-nowrap",
                        key && "cursor-pointer select-none hover:text-slate-300",
                      )}
                      onClick={() => key && toggleSort(key)}
                      scope="col"
                    >
                      {label}
                      {key && <SortIcon active={sortKey === key} dir={sortDir} />}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan={9} className="px-6 py-10 text-center text-sm text-slate-500">Loading scans...</td>
                  </tr>
                ) : scans.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="px-6 py-10 text-center text-sm text-slate-500">No scans match your filters.</td>
                  </tr>
                ) : (
                  scans.map((scan) => (
                    <tr
                      key={scan.job_id}
                      className={cn(
                        "border-b border-white/5 transition-colors",
                        scan.awaiting_user_decision && "bg-amber-500/[0.06] border-l-2 border-amber-500/40",
                      )}
                    >
                      <td className="px-4 py-3">
                        <input
                          type="checkbox"
                          checked={selectedIds.has(scan.job_id)}
                          onChange={() => toggleSelectOne(scan.job_id)}
                          aria-label={`Select scan ${scan.target}`}
                          className="h-4 w-4 rounded border-white/20 bg-transparent accent-blue-500"
                        />
                      </td>
                      <td className="px-4 py-3 text-sm font-medium text-slate-200 whitespace-nowrap">{scan.target}</td>
                      <td className="px-4 py-3 whitespace-nowrap"><StatusChip status={scan.status} /></td>
                      <td className="px-4 py-3 whitespace-nowrap min-w-[140px]">
                        <div className="flex items-center gap-2">
                          <ProgressBar value={scan.progress} className="!h-2 w-20" />
                          <span className="text-xs text-slate-400">{scan.progress}%</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-sm text-slate-400 whitespace-nowrap">{moduleLabel(scan.current_module)}</td>
                      <td className="px-4 py-3 text-sm font-semibold text-slate-300 whitespace-nowrap">
                        {scan.overall_score ?? "—"}
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-500 whitespace-nowrap">
                        {new Date(scan.created_at).toLocaleString()}
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-500 whitespace-nowrap">
                        {new Date(scan.updated_at ?? scan.created_at).toLocaleString()}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          <Link
                            href={`/scan/${scan.job_id}/status`}
                            className="px-2.5 py-1 rounded-lg bg-white/5 border border-white/10 text-slate-300 text-xs hover:bg-white/10 transition-colors"
                          >
                            Status
                          </Link>
                          {scan.status === "complete" ? (
                            <Link
                              href={`/scan/${scan.job_id}/report`}
                              className="px-2.5 py-1 rounded-lg bg-white/5 border border-white/10 text-slate-300 text-xs hover:bg-white/10 transition-colors"
                            >
                              Report
                            </Link>
                          ) : (
                            <span
                              title="Report available once the scan completes"
                              className="px-2.5 py-1 rounded-lg bg-white/5 border border-white/5 text-slate-600 text-xs cursor-not-allowed"
                            >
                              Report
                            </span>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Footer + pagination */}
          <div className="flex flex-wrap items-center justify-between gap-3 px-6 py-3 border-t border-white/8 text-xs text-slate-500">
            <span>
              Showing {scans.length} of {total} scans
              {error && <span className="ml-2 text-amber-400">{error}</span>}
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={page <= 1}
                onClick={() => updateUrl({ page: page - 1 })}
                className="px-2.5 py-1 rounded-lg bg-white/5 border border-white/10 text-slate-300 disabled:opacity-30 disabled:cursor-not-allowed hover:bg-white/10 transition-colors"
              >
                Prev
              </button>
              <span>Page {page} of {totalPages}</span>
              <button
                type="button"
                disabled={page >= totalPages}
                onClick={() => updateUrl({ page: page + 1 })}
                className="px-2.5 py-1 rounded-lg bg-white/5 border border-white/10 text-slate-300 disabled:opacity-30 disabled:cursor-not-allowed hover:bg-white/10 transition-colors"
              >
                Next
              </button>
            </div>
          </div>
        </div>
      </div>
    </main>
  )
}
