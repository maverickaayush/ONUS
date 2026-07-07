"use client"

import { useEffect, useRef, useState } from "react"
import { cn } from "@/lib/utils"
import type { ScanStatus } from "@/lib/api"

// ─── Severity Types ──────────────────────────────────────────────────────────
export type Severity = "Critical" | "High" | "Medium" | "Low" | "Informational"

export const SEVERITY_CONFIG: Record<
  Severity,
  { text: string; chip: string; dot: string; hex: string; glow: string }
> = {
  Critical: {
    text: "text-red-400",
    chip: "bg-red-500/10 text-red-300 border-red-500/30",
    dot: "bg-red-500",
    hex: "#EF4444",
    glow: "rgba(239,68,68,0.2)",
  },
  High: {
    text: "text-orange-400",
    chip: "bg-orange-500/10 text-orange-300 border-orange-500/30",
    dot: "bg-orange-500",
    hex: "#F97316",
    glow: "rgba(249,115,22,0.2)",
  },
  Medium: {
    text: "text-yellow-400",
    chip: "bg-yellow-500/10 text-yellow-300 border-yellow-500/30",
    dot: "bg-yellow-500",
    hex: "#EAB308",
    glow: "rgba(234,179,8,0.2)",
  },
  Low: {
    text: "text-blue-400",
    chip: "bg-blue-500/10 text-blue-300 border-blue-500/30",
    dot: "bg-blue-500",
    hex: "#3B82F6",
    glow: "rgba(59,130,246,0.2)",
  },
  Informational: {
    text: "text-slate-400",
    chip: "bg-slate-500/10 text-slate-300 border-slate-500/30",
    dot: "bg-slate-500",
    hex: "#6B7280",
    glow: "rgba(107,114,128,0.2)",
  },
}

function normalizeSeverity(severity: string): Severity {
  const normalized =
    severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase()
  if (normalized === "Info") return "Informational"
  return (
    (["Critical", "High", "Medium", "Low", "Informational"].includes(normalized)
      ? normalized
      : "Informational") as Severity
  )
}

// ─── SeverityBadge ───────────────────────────────────────────────────────────
export function SeverityBadge({
  severity,
  size = "sm",
}: {
  severity: string
  size?: "xs" | "sm" | "md"
}) {
  const mapped = normalizeSeverity(severity)
  const cfg = SEVERITY_CONFIG[mapped]
  const isCritical = mapped === "Critical"

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 font-medium tracking-wide rounded-full border",
        cfg.chip,
        isCritical && "vapt-critical-pulse",
        size === "xs" && "px-2 py-0.5 text-[10px]",
        size === "sm" && "px-2.5 py-0.5 text-xs",
        size === "md" && "px-3 py-1 text-sm",
      )}
    >
      <span className={cn("h-1.5 w-1.5 rounded-full", cfg.dot)} />
      {mapped}
    </span>
  )
}

// ─── ModuleChip ──────────────────────────────────────────────────────────────
export function ModuleChip({ module }: { module: string }) {
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-medium bg-white/5 text-slate-400 border border-white/10 uppercase tracking-wide">
      {module}
    </span>
  )
}

// ─── useCountUp ──────────────────────────────────────────────────────────────
export function useCountUp(target: number, duration = 800) {
  const [value, setValue] = useState(0)
  const startRef = useRef<number | null>(null)

  useEffect(() => {
    let raf = 0
    const tick = (ts: number) => {
      if (startRef.current === null) startRef.current = ts
      const elapsed = ts - startRef.current
      const progress = Math.min(elapsed / duration, 1)
      // easeOutCubic
      const eased = 1 - Math.pow(1 - progress, 3)
      setValue(Math.round(eased * target))
      if (progress < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [target, duration])

  return value
}

// ─── SummaryCard ─────────────────────────────────────────────────────────────
// Generalized from a severity-specific card (was report-dashboard.tsx-local,
// keyed off SEVERITY_CONFIG) to plain color props, so any glowing count-up
// stat card (severity counts, scan-status counts, etc.) can reuse it instead
// of duplicating the visual.
export function SummaryCard({
  label,
  count,
  hex,
  glow,
  textClass,
}: {
  label: string
  count: number
  hex: string
  glow: string
  textClass: string
}) {
  const display = useCountUp(count, 800)
  return (
    <div
      className="group relative rounded-2xl border border-white/8 backdrop-blur-sm bg-white/5 p-4 flex flex-col items-center gap-1 overflow-hidden transition-all duration-200 hover:-translate-y-0.5 hover:bg-white/8 hover:border-white/15"
      style={{ borderTop: `3px solid ${hex}` }}
    >
      <div
        className="pointer-events-none absolute -top-8 h-16 w-16 rounded-full blur-2xl opacity-40 transition-opacity group-hover:opacity-70"
        style={{ background: glow }}
      />
      <span
        className={cn("relative text-3xl font-black", textClass)}
        style={{ filter: `drop-shadow(0 0 10px ${glow})` }}
      >
        {display}
      </span>
      <span className="relative text-[11px] font-medium uppercase tracking-wide text-slate-400">
        {label}
      </span>
    </div>
  )
}

// ─── RiskScoreRing ───────────────────────────────────────────────────────────
export function RiskScoreRing({ score }: { score: number }) {
  const isHigh = score >= 70
  const isMed = score >= 40 && score < 70

  const color = isHigh ? "#EF4444" : isMed ? "#FBBF24" : "#34D399"
  const textColor = isHigh
    ? "text-red-400"
    : isMed
      ? "text-amber-400"
      : "text-emerald-400"
  const label = isHigh ? "HIGH RISK" : isMed ? "MODERATE RISK" : "LOW RISK"
  const badgeChip = isHigh
    ? "bg-red-500/10 text-red-300 border-red-500/30"
    : isMed
      ? "bg-amber-500/10 text-amber-300 border-amber-500/30"
      : "bg-emerald-500/10 text-emerald-300 border-emerald-500/30"

  const size = 200
  const stroke = 12
  const radius = (size - stroke) / 2
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (score / 100) * circumference

  const displayScore = useCountUp(score, 1500)

  return (
    <div className="flex flex-col items-center">
      <span className="text-xs font-medium uppercase tracking-widest text-slate-500 mb-4">
        Overall Risk Score
      </span>
      <div className="relative" style={{ width: size, height: size }}>
        <svg
          width={size}
          height={size}
          className="-rotate-90"
          aria-hidden="true"
        >
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="rgba(255,255,255,0.06)"
            strokeWidth={stroke}
          />
          <circle
            className="vapt-ring-progress"
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={circumference}
            style={
              {
                "--ring-circumference": `${circumference}`,
                "--ring-offset": `${offset}`,
                filter: `drop-shadow(0 0 8px ${color}66)`,
              } as React.CSSProperties
            }
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span
            className={cn("text-7xl font-black leading-none", textColor)}
            style={{ filter: `drop-shadow(0 0 16px ${color}55)` }}
          >
            {displayScore}
          </span>
          <span className="text-sm font-medium text-slate-500 mt-1">/ 100</span>
        </div>
      </div>
      <span
        className={cn(
          "mt-4 inline-flex items-center px-3 py-1 rounded-full border text-xs font-semibold tracking-wide",
          badgeChip,
        )}
      >
        {label}
      </span>
    </div>
  )
}

// ─── StatusChip ──────────────────────────────────────────────────────────────
// Widened from module-only status (queued|running|complete|failed) to the
// full scan-level ScanStatus union - every existing module-row call site
// keeps working unchanged since those 4 values are still valid inputs.
export function StatusChip({
  status,
}: {
  status: ScanStatus
}) {
  const spinner = (
    <svg
      className="animate-spin h-3 w-3 mr-1.5"
      viewBox="0 0 24 24"
      fill="none"
      style={{ filter: "drop-shadow(0 0 4px rgba(59,130,246,0.6))" }}
    >
      <circle
        className="opacity-25"
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="4"
      />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"
      />
    </svg>
  )
  const map = {
    queued: {
      label: "Queued",
      cls: "bg-slate-500/10 text-slate-400 border-slate-500/20",
      icon: null,
    },
    running: {
      label: "Running",
      cls: "bg-blue-500/10 text-blue-400 border-blue-500/30",
      icon: spinner,
    },
    analysing: {
      label: "Analysing",
      cls: "bg-purple-500/10 text-purple-400 border-purple-500/30",
      icon: spinner,
    },
    awaiting_user_decision: {
      label: "Awaiting Decision",
      // Amber matches decision-modal.tsx's existing "needs attention" convention.
      cls: "bg-amber-500/10 text-amber-400 border-amber-500/30",
      icon: null,
    },
    cancelled: {
      label: "Cancelled",
      cls: "bg-slate-500/10 text-slate-400 border-slate-500/20",
      icon: null,
    },
    complete: {
      label: "Complete",
      cls: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
      icon: (
        <svg
          className="h-3 w-3 mr-1.5 vapt-scale-in"
          viewBox="0 0 20 20"
          fill="currentColor"
        >
          <path
            fillRule="evenodd"
            d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
            clipRule="evenodd"
          />
        </svg>
      ),
    },
    failed: {
      label: "Failed",
      cls: "bg-red-500/10 text-red-400 border-red-500/20",
      icon: (
        <svg
          className="h-3 w-3 mr-1.5"
          viewBox="0 0 20 20"
          fill="currentColor"
        >
          <path
            fillRule="evenodd"
            d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z"
            clipRule="evenodd"
          />
        </svg>
      ),
    },
  }
  const { label, cls, icon } = map[status]
  return (
    <span
      className={cn(
        "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium tracking-wide border transition-all duration-300",
        cls,
      )}
    >
      {icon}
      {label}
    </span>
  )
}

// ─── ProgressBar ─────────────────────────────────────────────────────────────
export function ProgressBar({
  value,
  className,
}: {
  value: number
  className?: string
}) {
  return (
    <div
      className={cn(
        "relative w-full h-3 bg-white/5 rounded-full overflow-hidden border border-white/5",
        className,
      )}
    >
      <div
        className="vapt-shimmer relative h-full rounded-full transition-all duration-500 overflow-hidden"
        style={{
          width: `${value}%`,
          background: "linear-gradient(90deg, #2563eb, #6366f1, #8b5cf6)",
        }}
      />
    </div>
  )
}
