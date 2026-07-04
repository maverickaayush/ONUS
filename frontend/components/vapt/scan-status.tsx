"use client"

import { useState, useEffect, useRef, useCallback } from "react"
import { useRouter } from "next/navigation"
import Link from "next/link"
import { ProgressBar, StatusChip } from "@/components/vapt/shared"
import { VaptBackground } from "@/components/vapt/background"
import { DecisionModal } from "@/components/vapt/decision-modal"
import { cn } from "@/lib/utils"
import { getScanStatus, postScanDecision, getScanModules } from "@/lib/api"
import type { ModuleStatus, ScanDecisionAction, ScanModuleInfo } from "@/lib/api"

interface ScanModule {
  id: string
  name: string
  icon: React.ReactNode
  status: ModuleStatus
}

// Keyed by the backend's icon_hint (see home-form.tsx for the same map/
// reasoning) - a hint not recognized yet falls back to GENERIC_ICON so a
// newly added module still renders a row.
const MODULE_ICONS: Record<string, React.ReactNode> = {
  network: (
    <svg viewBox="0 0 20 20" fill="currentColor" className="h-4 w-4" aria-hidden="true">
      <path d="M9 9a2 2 0 114 0 2 2 0 01-4 0z" />
      <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-13a4 4 0 00-3.446 6.032l-2.261 2.26a1 1 0 101.414 1.415l2.261-2.261A4 4 0 1011 5z" clipRule="evenodd" />
    </svg>
  ),
  web: (
    <svg viewBox="0 0 20 20" fill="currentColor" className="h-4 w-4" aria-hidden="true">
      <path fillRule="evenodd" d="M4.083 9h1.946c.089-1.546.383-2.97.837-4.118A6.004 6.004 0 004.083 9zM10 2a8 8 0 100 16A8 8 0 0010 2zm0 2c-.076 0-.232.032-.465.262-.238.234-.497.623-.737 1.182-.389.907-.673 2.142-.766 3.556h3.936c-.093-1.414-.377-2.649-.766-3.556-.24-.56-.5-.948-.737-1.182C10.232 4.032 10.076 4 10 4zm3.971 5c-.089-1.546-.383-2.97-.837-4.118A6.004 6.004 0 0115.917 9h-1.946zm-2.003 2H8.032c.093 1.414.377 2.649.766 3.556.24.56.5.948.737 1.182.233.23.389.262.465.262.076 0 .232-.032.465-.262.238-.234.498-.623.737-1.182.389-.907.673-2.142.766-3.556zm1.166 4.118c.454-1.147.748-2.572.837-4.118h1.946a6.004 6.004 0 01-2.783 4.118zm-6.268 0C6.412 13.97 6.118 12.546 6.03 11H4.083a6.004 6.004 0 002.783 4.118z" clipRule="evenodd" />
    </svg>
  ),
  lock: (
    <svg viewBox="0 0 20 20" fill="currentColor" className="h-4 w-4" aria-hidden="true">
      <path fillRule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clipRule="evenodd" />
    </svg>
  ),
  list: (
    <svg viewBox="0 0 20 20" fill="currentColor" className="h-4 w-4" aria-hidden="true">
      <path fillRule="evenodd" d="M3 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h8a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h6a1 1 0 110 2H4a1 1 0 01-1-1z" clipRule="evenodd" />
    </svg>
  ),
  alert: (
    <svg viewBox="0 0 20 20" fill="currentColor" className="h-4 w-4" aria-hidden="true">
      <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
    </svg>
  ),
  fingerprint: (
    <svg viewBox="0 0 20 20" fill="currentColor" className="h-4 w-4" aria-hidden="true">
      <path fillRule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clipRule="evenodd" />
    </svg>
  ),
  target: (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" className="h-4 w-4" aria-hidden="true">
      <circle cx="10" cy="10" r="7" />
      <circle cx="10" cy="10" r="3.5" />
      <circle cx="10" cy="10" r="0.5" fill="currentColor" stroke="none" />
    </svg>
  ),
  folder: (
    <svg viewBox="0 0 20 20" fill="currentColor" className="h-4 w-4" aria-hidden="true">
      <path d="M2 6a2 2 0 012-2h4.586a1 1 0 01.707.293L10.414 5H16a2 2 0 012 2v7a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
    </svg>
  ),
}

const GENERIC_ICON = (
  <svg viewBox="0 0 20 20" fill="currentColor" className="h-4 w-4" aria-hidden="true">
    <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
  </svg>
)

// Hardcoded, not fetched: this describes a *process sequence* inside
// scan_orchestrator.py's _finalize() (Python control flow), not a
// queryable list of entities the way modules are - there's no natural
// "list the pipeline stages" API to build without inventing one purely to
// describe code structure. Confirmed against _finalize()'s actual 4
// top-level try/except stages (aggregate -> verify -> score+describe
// combined -> PDF), plus the initial scan dispatch: Scan, Aggregate,
// Verify, AI Analysis, PDF Report. If _finalize()'s stage sequence changes,
// update this array to match - it's the one hardcoded list in this file
// deliberately left that way (see the project docs's scan-modules note for why
// the module list above isn't).
const FLOW_NODES = ["Scan", "Aggregate", "Verify", "AI Analysis", "PDF Report"]

export function ScanStatus({ jobId, domain: initialDomain }: { jobId: string; domain: string }) {
  const router = useRouter()
  const [domain, setDomain] = useState(initialDomain || "")
  // Canonical module list - fetched from GET /api/scan/modules, not
  // hardcoded, so a module added on the backend shows up here without a
  // frontend code change (same source home-form.tsx's "Covers:" badges use).
  const [moduleDefs, setModuleDefs] = useState<ScanModuleInfo[]>([])
  const [modules, setModules] = useState<ScanModule[]>([])
  const [progress, setProgress] = useState(0)
  const [scanStatus, setScanStatus] = useState<string>("queued")
  const [startedAt, setStartedAt] = useState<Date | null>(null)
  const [elapsed, setElapsed] = useState(0)
  const [redirecting, setRedirecting] = useState(false)
  const [error, setError] = useState("")
  const [moduleErrors, setModuleErrors] = useState<Record<string, string>>({})
  const [canRetry, setCanRetry] = useState(false)

  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const elapsedRef  = useRef<ReturnType<typeof setInterval> | null>(null)

  const isFinal = scanStatus === "complete" || scanStatus === "failed" || scanStatus === "cancelled"

  useEffect(() => {
    getScanModules()
      .then(setModuleDefs)
      .catch(() => {
        // Module rows just stay empty until the next successful fetch -
        // the status poll below still works independently.
      })
  }, [])

  // Client-side elapsed timer driven by started_at
  useEffect(() => {
    if (!startedAt) return
    elapsedRef.current = setInterval(() => {
      setElapsed(Math.floor((Date.now() - startedAt.getTime()) / 1000))
    }, 1000)
    return () => {
      if (elapsedRef.current) clearInterval(elapsedRef.current)
    }
  }, [startedAt])

  const poll = useCallback(async () => {
    if (document.hidden) return
    try {
      const data = await getScanStatus(jobId)
      setDomain(data.domain || jobId)
      setProgress(data.progress ?? 0)
      setScanStatus(data.status)
      setModuleErrors(data.module_errors ?? {})
      setCanRetry(data.can_retry ?? false)
      if (data.started_at && !startedAt) {
        setStartedAt(new Date(data.started_at))
      }

      // moduleDefs ids match data.modules keys directly now (both derive
      // from the same backend SCAN_MODULES list) - no id-translation layer.
      setModules(moduleDefs.map((m) => ({
        id: m.id,
        name: m.label,
        icon: MODULE_ICONS[m.icon_hint] ?? GENERIC_ICON,
        status: (data.modules[m.id] as ModuleStatus) ?? "queued",
      })))

      if (data.status === "complete" && !redirecting) {
        setRedirecting(true)
        if (intervalRef.current) clearInterval(intervalRef.current)
        setTimeout(() => router.push(`/scan/${jobId}/report`), 1500)
      } else if (data.status === "failed" || data.status === "cancelled") {
        if (intervalRef.current) clearInterval(intervalRef.current)
      }
    } catch (err: unknown) {
      const status = (err as { status?: number })?.status
      if (status === 404) {
        setError("Scan not found")
      } else {
        setError("Connection lost - retrying...")
      }
    }
  }, [jobId, redirecting, router, startedAt, moduleDefs])

  useEffect(() => {
    poll()
    intervalRef.current = setInterval(poll, 3000)

    const onVisibility = () => {
      if (!document.hidden && !isFinal) poll()
    }
    document.addEventListener("visibilitychange", onVisibility)

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current)
      document.removeEventListener("visibilitychange", onVisibility)
    }
  }, [poll, isFinal])

  const formatElapsed = (s: number) => {
    const m = Math.floor(s / 60)
    const sec = s % 60
    return m > 0 ? `${m}m ${sec}s` : `${sec}s`
  }

  const allDone = scanStatus === "complete"
  const failed  = scanStatus === "failed"
  const cancelled = scanStatus === "cancelled"
  const awaitingDecision = scanStatus === "awaiting_user_decision"

  const handleDecide = async (action: ScanDecisionAction) => {
    try {
      const data = await postScanDecision(jobId, action)
      setScanStatus(data.status)
    } catch {
      setError("Failed to submit decision - retrying...")
    }
  }

  // 404 or permanent error
  if (error === "Scan not found") {
    return (
      <main className="vapt-noise relative min-h-[calc(100vh-56px)] flex items-center justify-center px-4 overflow-hidden">
        <VaptBackground />
        <div className="relative z-10 text-center space-y-4">
          <p className="text-slate-300 text-lg font-medium">Scan not found</p>
          <Link href="/" className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-white/5 border border-white/10 text-slate-300 text-sm hover:bg-white/10 transition-colors">
            Start new scan
          </Link>
        </div>
      </main>
    )
  }

  return (
    <main className="vapt-noise relative min-h-[calc(100vh-56px)] py-10 px-4 overflow-hidden">
      <VaptBackground />

      <div className="relative z-10 max-w-2xl mx-auto space-y-5">
        {/* Header card */}
        <div className="vapt-fade-up backdrop-blur-sm bg-white/5 border border-white/8 rounded-2xl p-6" style={{ animationDelay: "0ms" }}>
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-4">
              {/* Pulsing shield */}
              <div className="relative h-11 w-11 flex-shrink-0">
                <div className={cn("absolute inset-0 rounded-full", !allDone && !failed && "vapt-pulse-ring")} />
                <div className="relative h-11 w-11 rounded-full bg-blue-500/15 border border-blue-500/30 flex items-center justify-center">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-5 w-5 text-blue-400" aria-hidden="true">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" strokeLinecap="round" strokeLinejoin="round" />
                    <path d="M9 12l2 2 4-4" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </div>
              </div>
              <div>
                <p className="text-xs font-medium text-slate-500 uppercase tracking-wide mb-1">Target Domain</p>
                <h1 className="text-xl font-bold tracking-tight text-slate-100">{domain || jobId}</h1>
              </div>
            </div>
            <span
              className={cn(
                "inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-sm font-medium",
                failed || cancelled
                  ? "bg-red-500/10 border border-red-500/30 text-red-300"
                  : awaitingDecision
                  ? "bg-amber-500/10 border border-amber-500/30 text-amber-300"
                  : "bg-blue-500/10 border border-blue-500/30 text-blue-300",
              )}
              style={!failed && !cancelled && !awaitingDecision ? { boxShadow: "0 0 18px -6px rgba(59,130,246,0.6)" } : undefined}
            >
              <span className={cn(
                "h-2 w-2 rounded-full",
                failed || cancelled ? "bg-red-400" : awaitingDecision ? "bg-amber-400" : "bg-blue-400 animate-pulse",
              )} />
              {allDone
                ? "Scan complete"
                : failed
                ? "Scan failed"
                : cancelled
                ? "Scan cancelled"
                : awaitingDecision
                ? "Awaiting decision"
                : scanStatus === "analysing"
                ? "AI analysis"
                : "Scan in progress"}
            </span>
          </div>

          {/* Progress bar */}
          <div className="mt-6">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-medium uppercase tracking-wide text-slate-400">Overall Progress</span>
              <span className="text-sm font-bold text-blue-400" style={{ filter: "drop-shadow(0 0 6px rgba(59,130,246,0.5))" }}>
                {progress}%
              </span>
            </div>
            <ProgressBar value={progress} />
          </div>

          <p className="mt-3 text-xs text-slate-500">
            {startedAt ? (
              <>Running for <span className="font-semibold text-slate-300">{formatElapsed(elapsed)}</span></>
            ) : (
              "Waiting for worker..."
            )}
          </p>
          {error && error !== "Scan not found" && (
            <p className="mt-2 text-xs text-amber-400">{error}</p>
          )}
        </div>

        {/* Module rows */}
        <div className="vapt-fade-up backdrop-blur-sm bg-white/5 border border-white/8 rounded-2xl overflow-hidden" style={{ animationDelay: "75ms" }}>
          <div className="px-6 py-3.5 border-b border-white/8">
            <h2 className="text-xs font-medium uppercase tracking-wide text-slate-400">Scan Modules</h2>
          </div>
          <ul className="divide-y divide-white/5">
            {modules.map((mod, i) => (
              <li
                key={mod.id}
                className={cn(
                  "vapt-fade-up flex items-center justify-between px-6 py-4 transition-all duration-500",
                  mod.status === "complete" && "bg-emerald-500/[0.04]",
                  mod.status === "running"  && "bg-blue-500/[0.04]",
                  mod.status === "failed"   && "bg-red-500/[0.04]",
                )}
                style={{ animationDelay: `${150 + i * 75}ms` }}
              >
                <div className="flex items-center gap-3">
                  <span className={cn(
                    "flex-shrink-0 transition-colors duration-300",
                    mod.status === "complete" ? "text-emerald-400"
                      : mod.status === "running"  ? "text-blue-400"
                      : mod.status === "failed"   ? "text-red-400"
                      : "text-slate-500",
                  )}>
                    {mod.icon}
                  </span>
                  <span className="text-sm font-medium text-slate-200">{mod.name}</span>
                </div>
                <StatusChip status={mod.status} />
              </li>
            ))}
          </ul>
        </div>

        {/* What happens next - flow diagram (only while running) */}
        {!allDone && !failed && !cancelled && (
          <div className="vapt-fade-up backdrop-blur-sm bg-white/5 border border-white/8 rounded-2xl p-6" style={{ animationDelay: "525ms" }}>
            <h2 className="text-xs font-medium uppercase tracking-wide text-slate-400 mb-5">What happens next?</h2>
            <div className="overflow-x-auto -mx-6 px-6">
              <div className="flex items-center justify-between gap-1 min-w-[420px]">
                {FLOW_NODES.map((node, i) => (
                  <div key={node} className="flex items-center flex-1 last:flex-none">
                    <div className="flex flex-col items-center gap-2 flex-shrink-0">
                      <div className="h-9 w-9 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-xs font-bold text-blue-300">
                        {i + 1}
                      </div>
                      <span className="text-[11px] text-slate-400 font-medium whitespace-nowrap">{node}</span>
                    </div>
                    {i < FLOW_NODES.length - 1 && (
                      <svg className="flex-1 h-px mx-1 min-w-4" preserveAspectRatio="none" viewBox="0 0 100 1" aria-hidden="true">
                        <line x1="0" y1="0.5" x2="100" y2="0.5" stroke="rgba(59,130,246,0.4)" strokeWidth="1" strokeDasharray="4 3"
                          style={{ strokeDashoffset: 200, animation: `vapt-dash-draw 1.2s ease-out ${0.7 + i * 0.25}s forwards` }} />
                      </svg>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Redirect notice on complete */}
        {allDone && (
          <div className="vapt-fade-up backdrop-blur-sm bg-emerald-500/10 border border-emerald-500/20 rounded-2xl p-5 flex items-center gap-4">
            <div className="h-10 w-10 rounded-full bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center flex-shrink-0">
              <svg className="h-5 w-5 text-emerald-400 vapt-scale-in" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
              </svg>
            </div>
            <div>
              <p className="text-sm font-semibold text-emerald-300">All modules complete</p>
              <p className="text-xs text-emerald-400/80 mt-0.5 flex items-center gap-1.5">
                <svg className="animate-spin h-3 w-3" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
                </svg>
                Redirecting to your report...
              </p>
            </div>
          </div>
        )}

        {/* Failed state */}
        {failed && (
          <div className="vapt-fade-up backdrop-blur-sm bg-red-500/10 border border-red-500/20 rounded-2xl p-5 flex items-center gap-4">
            <div className="h-10 w-10 rounded-full bg-red-500/15 border border-red-500/30 flex items-center justify-center flex-shrink-0">
              <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="flex-1">
              <p className="text-sm font-semibold text-red-300">Scan failed</p>
              <p className="text-xs text-red-400/80 mt-0.5">One or more modules encountered an error.</p>
            </div>
            <Link href="/" className="px-4 py-2 rounded-xl bg-white/5 border border-white/10 text-slate-300 text-sm hover:bg-white/10 transition-colors">
              New scan
            </Link>
          </div>
        )}

        {/* Cancelled state */}
        {cancelled && (
          <div className="vapt-fade-up backdrop-blur-sm bg-white/5 border border-white/10 rounded-2xl p-5 flex items-center gap-4">
            <div className="flex-1">
              <p className="text-sm font-semibold text-slate-300">Scan cancelled</p>
              <p className="text-xs text-slate-500 mt-0.5">The operator cancelled this scan after module failures.</p>
            </div>
            <Link href="/" className="px-4 py-2 rounded-xl bg-white/5 border border-white/10 text-slate-300 text-sm hover:bg-white/10 transition-colors">
              New scan
            </Link>
          </div>
        )}
      </div>

      {awaitingDecision && (
        <DecisionModal moduleErrors={moduleErrors} canRetry={canRetry} onDecide={handleDecide} />
      )}
    </main>
  )
}
