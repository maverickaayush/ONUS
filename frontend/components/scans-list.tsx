'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import Link from 'next/link'
import { useRouter, useSearchParams } from 'next/navigation'
import { Activity, CircleCheck, CircleX, Plus, RefreshCw, TimerReset } from 'lucide-react'
import {
  getScanModules,
  getScans,
  type ScanListCounts,
  type ScanListResponse,
  type ScanModuleInfo,
} from '@/lib/api'
import { cn, formatDateTime } from '@/lib/format'
import { Panel, ProgressBar, StatusPill } from './ui'
import { Plate } from './decor'

const PAGE_SIZE = 20
const POLL_MS = 12000

const TABS = [
  { key: '', label: 'All' },
  { key: 'running', label: 'Running' },
  { key: 'awaiting_user_decision', label: 'Awaiting Decision' },
  { key: 'completed', label: 'Completed' },
  { key: 'failed', label: 'Failed' },
]

type SortCol = 'target' | 'status' | 'created_at' | 'updated_at'

export function ScansList() {
  const router = useRouter()
  const params = useSearchParams()

  const status = params.get('status') || ''
  const search = params.get('search') || ''
  const sort = (params.get('sort') as SortCol) || 'created_at'
  const order = (params.get('order') as 'asc' | 'desc') || 'desc'
  const page = Math.max(1, parseInt(params.get('page') || '1', 10) || 1)

  const [data, setData] = useState<ScanListResponse | null>(null)
  const [counts, setCounts] = useState<ScanListCounts | null>(null)
  const [loading, setLoading] = useState(true)
  const [connLost, setConnLost] = useState(false)
  const [searchInput, setSearchInput] = useState(search)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [moduleLabels, setModuleLabels] = useState<Record<string, string>>({})

  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const paramsRef = useRef({ status, search, sort, order, page })
  paramsRef.current = { status, search, sort, order, page }

  useEffect(() => {
    setSearchInput(search)
  }, [search])

  useEffect(() => {
    getScanModules()
      .then((mods: ScanModuleInfo[]) =>
        setModuleLabels(Object.fromEntries(mods.map((m) => [m.id, m.label]))),
      )
      .catch(() => {})
  }, [])

  const load = useCallback(async (showLoading: boolean) => {
    if (showLoading) setLoading(true)
    const p = paramsRef.current
    try {
      const res = await getScans({
        status: p.status || undefined,
        search: p.search || undefined,
        sort: p.sort,
        order: p.order,
        page: p.page,
        page_size: PAGE_SIZE,
      })
      setData(res)
      setCounts(res.counts) // whole-table counts - never zeroed by a filter
      setConnLost(false)
      // Reschedule only while something is active anywhere in the dataset.
      if (timerRef.current) clearTimeout(timerRef.current)
      if (res.counts.running > 0 || res.counts.awaiting_user_decision > 0) {
        timerRef.current = setTimeout(() => load(false), POLL_MS)
      }
    } catch {
      setConnLost(true) // keep last-known-good table on screen
      if (timerRef.current) clearTimeout(timerRef.current)
      timerRef.current = setTimeout(() => load(false), POLL_MS)
    } finally {
      if (showLoading) setLoading(false)
    }
  }, [])

  // Refetch whenever URL-driven params change.
  useEffect(() => {
    load(true)
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current)
    }
  }, [status, search, sort, order, page, load])

  // Resume polling on tab refocus.
  useEffect(() => {
    const onVis = () => {
      if (!document.hidden) load(false)
    }
    document.addEventListener('visibilitychange', onVis)
    return () => document.removeEventListener('visibilitychange', onVis)
  }, [load])

  const updateUrl = useCallback(
    (next: Partial<{ status: string; search: string; sort: string; order: string; page: number }>) => {
      const merged = { status, search, sort, order, page, ...next }
      const qs = new URLSearchParams()
      if (merged.status) qs.set('status', merged.status)
      if (merged.search) qs.set('search', merged.search)
      if (merged.sort && merged.sort !== 'created_at') qs.set('sort', merged.sort)
      if (merged.order && merged.order !== 'desc') qs.set('order', merged.order)
      if (merged.page && merged.page > 1) qs.set('page', String(merged.page))
      const s = qs.toString()
      router.push(s ? `/scans?${s}` : '/scans')
    },
    [router, status, search, sort, order, page],
  )

  function toggleSort(col: SortCol) {
    if (sort === col) updateUrl({ order: order === 'asc' ? 'desc' : 'asc', page: 1 })
    else updateUrl({ sort: col, order: 'asc', page: 1 })
  }

  const rows = data?.scans ?? []
  const totalPages = data?.total_pages ?? 1
  const total = data?.total ?? 0

  const allSelected = rows.length > 0 && rows.every((r) => selected.has(r.job_id))
  function toggleAll() {
    setSelected((prev) => {
      const next = new Set(prev)
      if (allSelected) rows.forEach((r) => next.delete(r.job_id))
      else rows.forEach((r) => next.add(r.job_id))
      return next
    })
  }

  const statCards = useMemo(
    () => [
      { label: 'Running', value: counts?.running ?? 0, icon: Activity, color: 'var(--color-accent)' },
      { label: 'Awaiting Decision', value: counts?.awaiting_user_decision ?? 0, icon: TimerReset, color: 'var(--color-high)' },
      { label: 'Completed', value: counts?.completed ?? 0, icon: CircleCheck, color: 'var(--color-cyan)' },
      { label: 'Failed', value: counts?.failed ?? 0, icon: CircleX, color: 'var(--color-crit)' },
    ],
    [counts],
  )

  return (
    <div className="relative w-full overflow-x-clip">
      {/* Filing and record-keeping. Right/left margins only - the table never
          sits on top of artwork. */}
      <Plate src="card-catalogue" rotate={-4} opacity={0.2} delay={0}
        className="right-[1%] top-[6%] hidden h-[400px] w-[400px] xl:block" />
      <Plate src="stacked-ledgers" rotate={5} opacity={0.2} delay={3.5}
        className="left-[1%] top-[30%] hidden h-[340px] w-[340px] xl:block" />
      <Plate src="index-card" rotate={-8} opacity={0.18} delay={7}
        className="bottom-[6%] right-[3%] hidden h-[320px] w-[320px] xl:block" />
    <div className="mx-auto w-full max-w-[1160px] px-6 py-10">
      <div className="mb-7 flex flex-wrap items-end justify-between gap-4 onus-fade-up">
        <div>
          <p className="mb-1.5 text-[11px] font-medium uppercase tracking-[0.24em] text-ink-faint">Ledger</p>
          <h1 className="text-[26px] font-semibold tracking-tight text-ink">Scans</h1>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => load(false)}
            className="flex items-center gap-2 rounded-md border border-line-strong px-3 py-2 text-[12.5px] font-medium text-ink-dim hover:bg-white/[0.03]"
          >
            <RefreshCw className="h-3.5 w-3.5" strokeWidth={1.7} />
            Refresh
          </button>
          <Link href="/scan/new" className="flex items-center gap-2 rounded-md bg-accent px-3.5 py-2 text-[12.5px] font-semibold text-white hover:bg-accent/90">
            <Plus className="h-3.5 w-3.5" strokeWidth={2} />
            New Scan
          </Link>
        </div>
      </div>

      {/* Stat cards - always whole-history counts */}
      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        {statCards.map((c, i) => {
          const Icon = c.icon
          return (
            <Panel key={c.label} className="flex items-center gap-3.5 p-4 onus-fade-up" style={{ animationDelay: `${i * 40}ms` }}>
              <span className="flex h-9 w-9 items-center justify-center rounded-md" style={{ backgroundColor: `color-mix(in srgb, ${c.color} 14%, transparent)` }}>
                <Icon className="h-[18px] w-[18px]" style={{ color: c.color }} strokeWidth={1.7} />
              </span>
              <div>
                <p className="tnum font-mono text-[22px] font-semibold leading-none text-ink">{c.value}</p>
                <p className="mt-1 text-[11px] text-ink-dim">{c.label}</p>
              </div>
            </Panel>
          )
        })}
      </div>

      {/* Tabs + search */}
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap gap-1 rounded-md border border-line bg-panel p-1">
          {TABS.map((t) => (
            <button
              key={t.key}
              onClick={() => updateUrl({ status: t.key, page: 1 })}
              className={cn(
                'rounded-[5px] px-3 py-1.5 text-[12px] font-medium transition-colors',
                status === t.key ? 'bg-accent/15 text-accent' : 'text-ink-dim hover:text-ink',
              )}
            >
              {t.label}
            </button>
          ))}
        </div>
        <form
          onSubmit={(e) => {
            e.preventDefault()
            updateUrl({ search: searchInput.trim(), page: 1 })
          }}
        >
          <input
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="Search target…"
            className="w-[220px] rounded-md border border-line bg-panel px-3 py-2 text-[12.5px] text-ink placeholder:text-ink-faint focus:border-accent/60 focus:outline-none"
            aria-label="Search scans by target"
          />
        </form>
      </div>

      {/* Selection bar */}
      {selected.size > 0 && (
        <div className="mb-3 flex items-center gap-3 rounded-md border border-accent/30 bg-accent/[0.07] px-3.5 py-2 text-[12.5px] text-accent-soft">
          <span className="tnum font-mono">{selected.size}</span> selected
          <button onClick={() => setSelected(new Set())} className="ml-auto text-ink-dim hover:text-ink">
            Clear
          </button>
        </div>
      )}

      {/* Table */}
      <Panel className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[920px] border-collapse text-left">
            <thead>
              <tr className="border-b border-line text-[10.5px] uppercase tracking-[0.1em] text-ink-faint">
                <th className="w-10 px-4 py-2.5">
                  <input type="checkbox" checked={allSelected} onChange={toggleAll} aria-label="Select all on page" className="accent-[var(--color-accent)]" />
                </th>
                <ScanTh label="Target" col="target" sort={sort} order={order} onSort={toggleSort} />
                <ScanTh label="Status" col="status" sort={sort} order={order} onSort={toggleSort} />
                <th className="whitespace-nowrap px-4 py-2.5 font-medium">Progress</th>
                <th className="whitespace-nowrap px-4 py-2.5 font-medium">Current Module</th>
                <th className="whitespace-nowrap px-4 py-2.5 font-medium">Risk</th>
                <ScanTh label="Started" col="created_at" sort={sort} order={order} onSort={toggleSort} />
                <ScanTh label="Last Updated" col="updated_at" sort={sort} order={order} onSort={toggleSort} />
                <th className="whitespace-nowrap px-4 py-2.5 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr>
                  <td colSpan={9} className="px-4 py-10 text-center text-[13px] text-ink-faint">
                    Loading scans…
                  </td>
                </tr>
              )}
              {!loading && rows.length === 0 && (
                <tr>
                  <td colSpan={9} className="px-4 py-16 text-center">
                    <div className="relative mx-auto flex max-w-[380px] flex-col items-center">
                      <Plate src="card-catalogue" rotate={-7} opacity={0.3}
                        className="left-1/2 top-[-26px] h-[190px] w-[190px] -translate-x-1/2" />
                      <p className="relative mt-[140px] text-[15px] font-semibold text-ink">
                        Nothing here yet
                      </p>
                      <p className="relative mt-1.5 text-[13px] leading-relaxed text-ink-dim">
                        No scans match your filters. Clear them, or start an assessment
                        and it will appear in this ledger.
                      </p>
                    </div>
                  </td>
                </tr>
              )}
              {!loading &&
                rows.map((r) => {
                  const isComplete = r.status === 'complete'
                  const cm =
                    r.current_module === null
                      ? '-'
                      : r.current_module === 'Analysing'
                        ? 'Analysing'
                        : moduleLabels[r.current_module] || r.current_module
                  return (
                    <tr key={r.job_id} className="border-b border-line/60 hover:bg-white/[0.02]">
                      <td className="px-4 py-3">
                        <input
                          type="checkbox"
                          checked={selected.has(r.job_id)}
                          onChange={() =>
                            setSelected((prev) => {
                              const next = new Set(prev)
                              if (next.has(r.job_id)) next.delete(r.job_id)
                              else next.add(r.job_id)
                              return next
                            })
                          }
                          aria-label={`Select ${r.target}`}
                          className="accent-[var(--color-accent)]"
                        />
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 font-mono text-[13px] text-ink">{r.target}</td>
                      <td className="px-4 py-3">
                        <StatusPill status={r.status} size="xs" />
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2" style={{ minWidth: 120 }}>
                          <ProgressBar value={r.progress} active={!['complete', 'failed', 'cancelled'].includes(r.status)} className="flex-1" />
                          <span className="tnum w-8 font-mono text-[11px] text-ink-dim">{r.progress}%</span>
                        </div>
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 text-[12px] text-ink-dim">{cm}</td>
                      <td className="whitespace-nowrap px-4 py-3 tnum font-mono text-[13px] text-ink-dim">
                        {r.overall_score ?? '-'}
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 text-[12px] text-ink-dim">{formatDateTime(r.created_at)}</td>
                      <td className="whitespace-nowrap px-4 py-3 text-[12px] text-ink-dim">{formatDateTime(r.updated_at)}</td>
                      <td className="whitespace-nowrap px-4 py-3 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <Link href={`/scan/${r.job_id}/status`} className="rounded-md border border-line px-2.5 py-1 text-[11.5px] text-ink-dim hover:border-line-strong hover:text-ink">
                            Status
                          </Link>
                          {isComplete ? (
                            <Link href={`/scan/${r.job_id}/report`} className="rounded-md border border-accent/40 px-2.5 py-1 text-[11.5px] text-accent-soft hover:bg-accent/[0.08]">
                              Report
                            </Link>
                          ) : (
                            <span
                              title="Available once the scan is complete."
                              className="cursor-not-allowed rounded-md border border-line px-2.5 py-1 text-[11.5px] text-ink-faint/60"
                            >
                              Report
                            </span>
                          )}
                        </div>
                      </td>
                    </tr>
                  )
                })}
            </tbody>
          </table>
        </div>
      </Panel>

      {/* Footer + pagination */}
      <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
        <p className="text-[12px] text-ink-faint">
          Showing {rows.length} of {total} scans
          {connLost && <span className="ml-2 text-high">· Connection lost - retrying…</span>}
        </p>
        <div className="flex items-center gap-2">
          <button
            disabled={page <= 1}
            onClick={() => updateUrl({ page: page - 1 })}
            className="rounded-md border border-line px-3 py-1.5 text-[12px] text-ink-dim disabled:cursor-not-allowed disabled:opacity-40 hover:enabled:bg-white/[0.03]"
          >
            Prev
          </button>
          <span className="tnum px-1 font-mono text-[12px] text-ink-dim">
            {page} / {totalPages}
          </span>
          <button
            disabled={page >= totalPages}
            onClick={() => updateUrl({ page: page + 1 })}
            className="rounded-md border border-line px-3 py-1.5 text-[12px] text-ink-dim disabled:cursor-not-allowed disabled:opacity-40 hover:enabled:bg-white/[0.03]"
          >
            Next
          </button>
        </div>
      </div>
    </div>
    </div>
  )
}

function ScanTh({
  label,
  col,
  sort,
  order,
  onSort,
}: {
  label: string
  col: SortCol
  sort: SortCol
  order: 'asc' | 'desc'
  onSort: (c: SortCol) => void
}) {
  const active = sort === col
  return (
    <th className="whitespace-nowrap px-4 py-2.5 font-medium">
      <button onClick={() => onSort(col)} className={cn('inline-flex items-center gap-1', active ? 'text-ink' : 'hover:text-ink-dim')}>
        {label}
        <span className="text-[9px]">{active ? (order === 'asc' ? '▲' : '▼') : '↕'}</span>
      </button>
    </th>
  )
}
