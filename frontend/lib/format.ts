import type { Severity } from './api'

export function cn(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(' ')
}

// Severity is a free string on the wire — normalize defensively.
export function normalizeSeverity(raw: string | undefined | null): Severity {
  const s = (raw || '').trim().toLowerCase()
  if (s === 'critical') return 'Critical'
  if (s === 'high') return 'High'
  if (s === 'medium') return 'Medium'
  if (s === 'low') return 'Low'
  return 'Informational'
}

export interface SeverityMeta {
  label: Severity
  short: string
  varName: string // css var
  order: number // Critical highest
}

export const SEVERITY: Record<Severity, SeverityMeta> = {
  Critical: { label: 'Critical', short: 'Critical', varName: 'var(--color-crit)', order: 5 },
  High: { label: 'High', short: 'High', varName: 'var(--color-high)', order: 4 },
  Medium: { label: 'Medium', short: 'Medium', varName: 'var(--color-med)', order: 3 },
  Low: { label: 'Low', short: 'Low', varName: 'var(--color-low)', order: 2 },
  Informational: { label: 'Informational', short: 'Info', varName: 'var(--color-info)', order: 1 },
}

export const SEVERITY_ORDER: Severity[] = [
  'Critical',
  'High',
  'Medium',
  'Low',
  'Informational',
]

// CVSS color band (frontend-only presentational rule over the raw float).
export function cvssColor(score: number): string {
  if (score >= 7) return 'var(--color-crit)'
  if (score >= 4) return 'var(--color-high)'
  return 'var(--color-low)'
}

// Risk-score band label (frontend-only, layered on the backend's raw integer).
export function riskBand(score: number): { label: string; color: string } {
  if (score >= 70) return { label: 'HIGH RISK', color: 'var(--color-crit)' }
  if (score >= 40) return { label: 'MODERATE RISK', color: 'var(--color-high)' }
  return { label: 'LOW RISK', color: '#4fae7c' }
}

// remediation arrives as ONE newline-joined string, never an array.
export function splitRemediation(remediation: unknown): string[] {
  if (Array.isArray(remediation)) {
    return (remediation as unknown[]).map((s) => String(s)).filter(Boolean)
  }
  if (typeof remediation === 'string') {
    const steps = remediation
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean)
    if (steps.length) return steps
  }
  return ['Review and remediate this finding per security best practices.']
}

// started_at is always UTC-suffixed ISO8601 — parse directly, do not localize.
export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return '-'
  const d = new Date(iso)
  if (isNaN(d.getTime())) return '-'
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export function formatElapsed(ms: number): string {
  if (ms < 0) ms = 0
  const total = Math.floor(ms / 1000)
  const h = Math.floor(total / 3600)
  const m = Math.floor((total % 3600) / 60)
  const s = total % 60
  const pad = (n: number) => String(n).padStart(2, '0')
  return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${pad(m)}:${pad(s)}`
}
