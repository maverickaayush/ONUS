'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { Check, ChevronRight, CircleDashed, Loader, X } from 'lucide-react'
import {
  ApiError,
  getScanModules,
  getScanStatus,
  postScanDecision,
  type ModuleStatus,
  type ScanDecisionAction,
  type ScanModuleInfo,
  type ScanStatusResponse,
} from '@/lib/api'
import { cn, formatElapsed } from '@/lib/format'
import { trackEvent } from '@/lib/analytics'
import { DecisionModal } from './decision-modal'
import { MarkNotFound, ModuleIcon, Panel, ProgressBar, SchematicCorners, StatusPill, Tooltip } from './ui'
import { Plate } from './decor'

const TERMINAL = ['complete', 'failed', 'cancelled']
const FLOW = ['Scan', 'Aggregate', 'Verify', 'AI Analysis', 'Report']

function flowIndex(status: string | undefined): number {
  if (status === 'analysing') return 3
  return 0 // queued / running / awaiting_user_decision all sit at the Scan stage
}

export function ScanStatus({ jobId }: { jobId: string }) {
  const router = useRouter()
  const [status, setStatus] = useState<ScanStatusResponse | null>(null)
  const [modules, setModules] = useState<ScanModuleInfo[]>([])
  const [error, setError] = useState<'notfound' | 'conn' | null>(null)
  const [now, setNow] = useState(() => Date.now())

  const isTerminal = !!status && TERMINAL.includes(status.status)

  useEffect(() => {
    getScanModules().then(setModules).catch(() => setModules([]))
  }, [])

  const poll = useCallback(async () => {
    try {
      const res = await getScanStatus(jobId)
      setStatus(res)
      setError(null)
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) setError('notfound')
      else setError('conn')
    }
  }, [jobId])

  // 3s poll loop - skips while tab hidden, one extra poll on refocus, cleared
  // on a terminal state (but NOT on awaiting_user_decision).
  useEffect(() => {
    if (error === 'notfound' || isTerminal) return
    poll()
    const iv = setInterval(() => {
      if (!document.hidden) poll()
    }, 3000)
    const onVis = () => {
      if (!document.hidden) poll()
    }
    document.addEventListener('visibilitychange', onVis)
    return () => {
      clearInterval(iv)
      document.removeEventListener('visibilitychange', onVis)
    }
  }, [poll, error, isTerminal])

  // Independent 1s elapsed ticker seeded from started_at.
  useEffect(() => {
    if (isTerminal) return
    const iv = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(iv)
  }, [isTerminal])

  // Auto-navigate to the report ~1.5s after completion.
  const redirectRef = useRef(false)
  useEffect(() => {
    if (status?.status === 'complete' && !redirectRef.current) {
      redirectRef.current = true
      // Anonymous completion signal — no domain/results. Guarded by redirectRef
      // so it fires exactly once per scan, not on every poll.
      trackEvent('scan_completed')
      const t = setTimeout(() => router.push(`/scan/${jobId}/report`), 1500)
      return () => clearTimeout(t)
    }
  }, [status?.status, jobId, router])

  const labelFor = useCallback(
    (id: string) => modules.find((m) => m.id === id)?.label ?? id,
    [modules],
  )

  async function handleDecide(action: ScanDecisionAction) {
    try {
      await postScanDecision(jobId, action)
    } catch {
      setError('conn')
    }
    // Retry/continue are async relative to their own response - never trust the
    // returned body; just poll and let the real transition surface.
    await poll()
  }

  if (error === 'notfound') {
    return (
      <CenterCard
        icon={<MarkNotFound className="h-6 w-6 text-ink-dim" />}
        title="Scan not found"
        body="No scan exists for this ID. It may have been mistyped or never created."
      />
    )
  }

  const startedMs = status?.started_at ? new Date(status.started_at).getTime() : null
  const elapsed = startedMs ? now - startedMs : 0
  const scanStatus = status?.status ?? 'queued'
  const progress = status?.progress ?? 0
  const moduleMap = status?.modules ?? {}
  const orderedModules =
    modules.length > 0
      ? modules
      : Object.keys(moduleMap).map((id) => ({ id, label: id, icon_hint: '', description: '' }))

  const awaiting =
    scanStatus === 'awaiting_user_decision' && status?.module_errors

  return (
    <div className="relative w-full overflow-x-clip">
      {/* Waiting and measurement - the page's entire subject. Margins only,
          well clear of the module list and the progress stepper. */}
      <Plate src="pressure-gauge" rotate={-7} opacity={0.22} delay={0}
        className="left-[2%] top-[26%] hidden h-[400px] w-[400px] 2xl:block" />
      <Plate src="hourglass" rotate={6} opacity={0.24} delay={3}
        className="right-[2%] top-[14%] hidden h-[340px] w-[340px] 2xl:block" />
      <Plate src="telegraph-key" rotate={-5} opacity={0.22} delay={6.5}
        className="bottom-[10%] right-[5%] hidden h-[330px] w-[330px] 2xl:block" />
    <div className="mx-auto w-full max-w-[860px] px-6 py-12">
      {/* Header */}
      <div className="mb-8 flex flex-wrap items-end justify-between gap-4 onus-fade-up">
        <div className="min-w-0 max-w-full">
          <p className="mb-1.5 text-[11px] font-medium uppercase tracking-[0.24em] text-ink-faint">Assessment</p>
          <Tooltip label={status?.domain ?? '-'}>
            <h1 className="truncate font-mono text-[26px] font-semibold tracking-tight text-ink">
              {status?.domain ?? '-'}
            </h1>
          </Tooltip>
        </div>
        <div className="flex items-center gap-4">
          <div className="text-right">
            <p className="text-[10px] uppercase tracking-[0.18em] text-ink-faint">Elapsed</p>
            <p className="tnum font-mono text-[18px] font-medium text-ink">{formatElapsed(elapsed)}</p>
          </div>
          <StatusPill status={scanStatus} />
        </div>
      </div>

      {/* Queued-for-capacity banner (hosted queue). Reassures the user the scan
          was accepted and will start on its own - never a "try again" dead end. */}
      {status?.waiting_for_capacity && (
        <div
          className="mb-8 flex items-center gap-3 rounded-[4px] border border-accent/30 bg-accent/[0.06] px-4 py-3 onus-fade-up"
          role="status"
        >
          <CircleDashed className="h-4 w-4 shrink-0 text-accent" strokeWidth={1.8} />
          <p className="text-[12.5px] text-ink-dim">
            {status.queue_position
              ? <>Queued: <span className="font-medium text-ink">#{status.queue_position} in line</span>.{' '}</>
              : <>Queued.{' '}</>}
            This scan was accepted and will start automatically as soon as a slot frees up. No action needed. This page updates live.
          </p>
        </div>
      )}

      {/* Progress */}
      <div className="mb-8 onus-fade-up" style={{ animationDelay: '40ms' }}>
        <div className="mb-2 flex items-center justify-between">
          <span className="text-[12px] text-ink-dim">Overall progress</span>
          <span className="tnum font-mono text-[13px] font-medium text-ink">{progress}%</span>
        </div>
        <ProgressBar value={progress} active={!isTerminal} />
      </div>

      {/* Flow diagram (while in progress) */}
      {!isTerminal && (
        <div className="mb-8 overflow-x-auto onus-fade-up" style={{ animationDelay: '80ms' }}>
          <div className="flex min-w-[560px] items-center gap-2">
            {FLOW.map((step, i) => {
              const active = i === flowIndex(scanStatus)
              const done = i < flowIndex(scanStatus)
              return (
                <div key={step} className="flex flex-1 items-center gap-2">
                  <div
                    className={cn(
                      'signage flex-1 rounded-[3px] border px-3 py-2.5 text-center text-[9px] transition-colors',
                      active
                        ? 'border-accent/60 bg-accent/[0.08] text-accent text-glow-cyan glow-cyan'
                        : done
                          ? 'border-accent/30 text-accent/70'
                          : 'border-line text-ink-faint',
                    )}
                  >
                    {step}
                  </div>
                  {i < FLOW.length - 1 && (
                    <div
                      className={cn(
                        'relative h-px w-7 shrink-0 overflow-hidden',
                        i < flowIndex(scanStatus) ? 'b-travel bg-accent/45' : 'bg-line',
                      )}
                    />
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Terminal banners */}
      {scanStatus === 'complete' && (
        <Panel className="mb-6 flex items-center gap-3 border-[var(--color-accent-deep)]/40 bg-[var(--color-accent-deep)]/[0.07] p-4 onus-fade-up">
          <Check className="h-5 w-5 text-[var(--color-cyan)]" strokeWidth={2} />
          <span className="text-[13.5px] text-ink">All modules complete - opening the report…</span>
        </Panel>
      )}
      {scanStatus === 'failed' && (
        <Panel className="mb-6 flex flex-wrap items-center justify-between gap-3 border-crit/40 bg-crit/[0.06] p-4 onus-fade-up">
          <span className="flex items-center gap-3 text-[13.5px] text-ink">
            <X className="h-5 w-5 text-crit" strokeWidth={2} />
            The scan failed and cannot continue.
          </span>
          <Link href="/scan/new" className="rounded-md bg-accent px-3.5 py-2 text-[12.5px] font-semibold text-white hover:bg-accent/90">
            Start a new scan
          </Link>
        </Panel>
      )}
      {scanStatus === 'cancelled' && (
        <Panel className="mb-6 flex flex-wrap items-center justify-between gap-3 p-4 onus-fade-up">
          <span className="flex items-center gap-3 text-[13.5px] text-ink-dim">
            <CircleDashed className="h-5 w-5 text-ink-faint" strokeWidth={1.7} />
            This scan was cancelled.
          </span>
          <Link href="/scan/new" className="rounded-md border border-line-strong px-3.5 py-2 text-[12.5px] font-medium text-ink hover:bg-white/[0.03]">
            Start a new scan
          </Link>
        </Panel>
      )}

      {/* Connection note */}
      {error === 'conn' && (
        <p className="mb-4 text-[12px] text-high">Connection lost - retrying…</p>
      )}

      {/* Module timeline */}
      <Panel className={cn('relative divide-y divide-line', awaiting && 'pointer-events-none opacity-40')}>
        <SchematicCorners />
        {orderedModules.map((m, i) => {
          const st = (moduleMap[m.id] ?? 'queued') as ModuleStatus
          return (
            <div key={m.id} className="flex items-center gap-3.5 px-4 py-3.5 onus-fade-up" style={{ animationDelay: `${i * 30}ms` }}>
              <ModuleIcon
                hint={m.icon_hint}
                className={cn(
                  'h-[18px] w-[18px] shrink-0',
                  st === 'complete' ? 'text-[var(--color-cyan)]' : st === 'running' ? 'text-accent' : st === 'failed' ? 'text-crit' : 'text-ink-faint',
                )}
              />
              <div className="flex-1">
                <p className="text-[13px] font-medium text-ink">{m.label}</p>
                {m.description && <p className="mt-0.5 line-clamp-1 text-[11.5px] text-ink-faint">{m.description}</p>}
              </div>
              <ModuleState status={st} />
            </div>
          )
        })}
      </Panel>

      {awaiting && (
        <DecisionModal
          moduleErrors={status!.module_errors!}
          canRetry={status!.can_retry ?? false}
          labelFor={labelFor}
          onDecide={handleDecide}
        />
      )}
    </div>
    </div>
  )
}

function ModuleState({ status }: { status: ModuleStatus }) {
  if (status === 'complete')
    return (
      <span className="flex items-center gap-1.5 text-[11.5px] font-medium text-[var(--color-cyan)]">
        <Check className="h-3.5 w-3.5 onus-scale-in" strokeWidth={2.4} /> Complete
      </span>
    )
  if (status === 'running')
    return (
      <span className="signage flex items-center gap-2 text-[10px] text-accent text-glow-cyan">
        {/* radar sweep - reserved exclusively for the running state */}
        <span className="b-radar relative inline-block h-3.5 w-3.5 rounded-full border border-accent/40" />
        Running
      </span>
    )
  if (status === 'failed')
    return (
      <span className="flex items-center gap-1.5 text-[11.5px] font-medium text-crit">
        <X className="h-3.5 w-3.5" strokeWidth={2.4} /> Failed
      </span>
    )
  return (
    <span className="flex items-center gap-1.5 text-[11.5px] font-medium text-ink-faint">
      <CircleDashed className="h-3.5 w-3.5" strokeWidth={1.8} /> Queued
    </span>
  )
}

function CenterCard({ icon, title, body }: { icon: React.ReactNode; title: string; body: string }) {
  return (
    <div className="mx-auto flex min-h-screen w-full max-w-[440px] flex-col items-center justify-center px-6 text-center">
      <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-lg border border-line bg-panel">{icon}</div>
      <h1 className="text-[19px] font-semibold text-ink">{title}</h1>
      <p className="mt-2 text-[13.5px] leading-relaxed text-ink-dim">{body}</p>
      <Link href="/scan/new" className="mt-6 rounded-md bg-accent px-4 py-2.5 text-[13px] font-semibold text-white hover:bg-accent/90">
        Start a new scan
      </Link>
    </div>
  )
}
