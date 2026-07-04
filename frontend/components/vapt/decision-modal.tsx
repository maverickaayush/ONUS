"use client"

import { useState } from "react"
import { cn } from "@/lib/utils"

const MODULE_LABELS: Record<string, string> = {
  recon: "Recon",
  webscan: "Web Scan",
  ssl_tls: "SSL / TLS",
  headers: "Headers",
  owasp: "OWASP Top 10",
  tech_fingerprint: "Tech Fingerprint",
  nuclei: "Nuclei CVE Scan",
  enumeration: "Dir Enumeration",
}

export function DecisionModal({
  moduleErrors,
  canRetry,
  onDecide,
}: {
  moduleErrors: Record<string, string>
  canRetry: boolean
  onDecide: (action: "retry" | "continue" | "cancel") => Promise<void>
}) {
  const [pending, setPending] = useState<"retry" | "continue" | "cancel" | null>(null)

  const decide = async (action: "retry" | "continue" | "cancel") => {
    setPending(action)
    try {
      await onDecide(action)
    } finally {
      setPending(null)
    }
  }

  const failedModules = Object.keys(moduleErrors)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center px-4 bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-lg backdrop-blur-sm bg-[#0b0f1a]/95 border border-white/10 rounded-2xl p-6 shadow-2xl">
        <div className="flex items-center gap-3 mb-4">
          <div className="h-9 w-9 rounded-full bg-amber-500/15 border border-amber-500/30 flex items-center justify-center flex-shrink-0">
            <svg className="h-4.5 w-4.5 text-amber-400" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
              <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
            </svg>
          </div>
          <div>
            <h2 className="text-sm font-semibold text-slate-100">Scan needs a decision</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              {failedModules.length} module{failedModules.length !== 1 ? "s" : ""} failed to complete.
            </p>
          </div>
        </div>

        <ul className="space-y-2 mb-5 max-h-48 overflow-y-auto">
          {failedModules.map((mod) => (
            <li key={mod} className="rounded-xl bg-red-500/[0.06] border border-red-500/20 px-3.5 py-2.5">
              <p className="text-xs font-medium text-red-300">{MODULE_LABELS[mod] ?? mod}</p>
              <p className="text-xs text-slate-400 mt-1 break-words">{moduleErrors[mod]}</p>
            </li>
          ))}
        </ul>

        <div className="flex flex-col gap-2">
          <button
            type="button"
            disabled={!canRetry || pending !== null}
            onClick={() => decide("retry")}
            className={cn(
              "px-4 py-2.5 rounded-xl text-sm font-medium transition-colors",
              canRetry
                ? "bg-blue-500/15 border border-blue-500/30 text-blue-300 hover:bg-blue-500/25"
                : "bg-white/[0.03] border border-white/10 text-slate-500 cursor-not-allowed",
            )}
            title={canRetry ? undefined : "Each module already used its one retry"}
          >
            {pending === "retry" ? "Retrying..." : canRetry ? "Retry Failed Modules" : "Retry unavailable (already retried once)"}
          </button>
          <button
            type="button"
            disabled={pending !== null}
            onClick={() => decide("continue")}
            className="px-4 py-2.5 rounded-xl text-sm font-medium bg-white/5 border border-white/10 text-slate-300 hover:bg-white/10 transition-colors disabled:opacity-50"
          >
            {pending === "continue" ? "Continuing..." : "Continue Without Failed Modules"}
          </button>
          <button
            type="button"
            disabled={pending !== null}
            onClick={() => decide("cancel")}
            className="px-4 py-2.5 rounded-xl text-sm font-medium bg-red-500/10 border border-red-500/20 text-red-300 hover:bg-red-500/20 transition-colors disabled:opacity-50"
          >
            {pending === "cancel" ? "Cancelling..." : "Cancel Scan"}
          </button>
        </div>
      </div>
    </div>
  )
}
