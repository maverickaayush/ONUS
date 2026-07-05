export type ScanStatus =
  | 'queued' | 'running' | 'analysing' | 'awaiting_user_decision' | 'complete' | 'failed' | 'cancelled'

export type ModuleStatus =
  | 'queued' | 'running' | 'complete' | 'failed'

export type ScanDecisionAction = 'retry' | 'continue' | 'cancel'

export interface ScanModuleInfo {
  id: string
  label: string
  icon_hint: string
  description: string
}

export interface ScanResponse {
  job_id: string
  status: ScanStatus
  domain: string
}

export interface ScanStatusResponse {
  job_id: string
  domain: string
  status: ScanStatus
  progress: number
  started_at: string | null
  modules: Record<string, ModuleStatus>
  // Only populated while status === 'awaiting_user_decision'.
  module_errors?: Record<string, string> | null
  can_retry?: boolean | null
}

export interface Finding {
  type: string
  title: string
  description?: string
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational'
  cvss_score: number
  cvss_vector?: string
  owasp_category?: string | null
  cve_reference?: string | null
  evidence: string
  remediation?: string | string[]
  priority?: number
  module: string
  found_by: string[]
  target: string
}

export interface FindingsResponse {
  executive_summary: string
  risk_score: number
  total_critical: number
  total_high: number
  total_medium: number
  total_low: number
  total_informational: number
  findings: Finding[]
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
    this.name = 'ApiError'
  }
}

async function handle<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}))
    const message =
      typeof detail.detail === 'string'
        ? detail.detail
        : detail.detail?.message || `HTTP ${res.status}`
    throw new ApiError(res.status, message)
  }
  return res.json() as Promise<T>
}

export interface AuthConfig {
  loginUrl: string
  username: string
  password: string
  usernameField?: string
  passwordField?: string
  loggedInIndicator?: string
}

export async function submitScan(
  domain: string,
  authorized: boolean,
  auth?: AuthConfig,
): Promise<ScanResponse> {
  const res = await fetch('/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      domain,
      authorized,
      // Omitted entirely (not `auth: null`) when not set, so the no-auth
      // request body is byte-identical to before this feature existed.
      ...(auth && {
        auth: {
          login_url: auth.loginUrl,
          username: auth.username,
          password: auth.password,
          ...(auth.usernameField && { username_field: auth.usernameField }),
          ...(auth.passwordField && { password_field: auth.passwordField }),
          ...(auth.loggedInIndicator && { logged_in_indicator: auth.loggedInIndicator }),
        },
      }),
    }),
  })
  return handle<ScanResponse>(res)
}

export async function getScanStatus(jobId: string): Promise<ScanStatusResponse> {
  const res = await fetch(`/api/scan/${jobId}/status`, { cache: 'no-store' })
  return handle<ScanStatusResponse>(res)
}

export async function postScanDecision(
  jobId: string,
  action: ScanDecisionAction,
): Promise<ScanStatusResponse> {
  const res = await fetch(`/api/scan/${jobId}/decision`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action }),
  })
  return handle<ScanStatusResponse>(res)
}

export async function getFindings(jobId: string): Promise<FindingsResponse> {
  const res = await fetch(`/api/scan/${jobId}/findings`, { cache: 'no-store' })
  return handle<FindingsResponse>(res)
}

export function reportPdfUrl(jobId: string): string {
  return `/api/scan/${jobId}/report`
}

export async function getScanModules(): Promise<ScanModuleInfo[]> {
  const res = await fetch('/api/scan/modules', { cache: 'no-store' })
  const data = await handle<{ modules: ScanModuleInfo[] }>(res)
  return data.modules
}
