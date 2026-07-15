// Typed client for the VAPT backend. Every field name, endpoint, status code
// and query-param below is the exact wire contract from FRONTEND_INTEGRATION_SPEC
// Sections 3–4. All requests are same-origin (/api/*) and proxied server-side
// by next.config.mjs — the browser never calls the backend cross-origin.

// ── Enums ───────────────────────────────────────────────────────────────────
export type ScanStatus =
  | 'queued'
  | 'running'
  | 'analysing'
  | 'awaiting_user_decision'
  | 'complete'
  | 'failed'
  | 'cancelled'

export type ModuleStatus = 'queued' | 'running' | 'complete' | 'failed'

export type ScanDecisionAction = 'retry' | 'continue' | 'cancel'

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational'

// ── Module metadata ─────────────────────────────────────────────────────────
export interface ScanModuleInfo {
  id: string
  label: string
  icon_hint: string
  description: string
}

// ── Scan creation ───────────────────────────────────────────────────────────
export interface AuthConfigWire {
  login_url: string
  username: string
  password: string
  username_field?: string
  password_field?: string
  logged_in_indicator?: string | null
  login_type?: 'auto' | 'form' | 'json'
  token_json_path?: string | null
  token_header?: string
  token_header_prefix?: string
}

export interface ScanRequestBody {
  domain: string
  authorized: boolean
  notes?: string
  auth?: AuthConfigWire
}

export interface ScanResponse {
  job_id: string
  status: ScanStatus
  domain: string
}

// ── Status ──────────────────────────────────────────────────────────────────
export interface ScanStatusResponse {
  job_id: string
  domain: string
  status: ScanStatus
  progress: number
  started_at: string | null
  modules: Record<string, ModuleStatus>
  module_errors?: Record<string, string> | null
  can_retry?: boolean | null
}

// ── Findings ────────────────────────────────────────────────────────────────
export interface ApiFinding {
  title: string
  description?: string
  severity: Severity
  cvss_score: number
  cvss_vector?: string
  owasp_category?: string | null
  cve_reference?: string | null
  evidence: string
  remediation?: string
  priority?: number
  module: string
  // Optional confidence-verification fields — genuinely optional, may be absent.
  confidence?: 'confirmed' | 'probable' | 'unverified'
  verification_note?: string
}

export interface FindingsResponse {
  executive_summary: string
  risk_score: number
  total_critical: number
  total_high: number
  total_medium: number
  total_low: number
  total_informational: number
  findings: ApiFinding[]
}

// ── Scans discovery list ────────────────────────────────────────────────────
export interface ScanListItem {
  job_id: string
  target: string
  status: ScanStatus
  created_at: string
  updated_at: string | null
  progress: number
  current_module: string | null
  overall_score: number | null
  awaiting_user_decision: boolean
  module_errors?: string[] | null
  modules_completed: number
  modules_total: number
}

export interface ScanListCounts {
  running: number
  awaiting_user_decision: number
  completed: number
  failed: number
  total: number
}

export interface ScanListResponse {
  scans: ScanListItem[]
  counts: ScanListCounts
  total: number
  page: number
  page_size: number
  total_pages: number
}

export interface ScanListParams {
  status?: string
  search?: string
  sort?: 'created_at' | 'updated_at' | 'status' | 'target'
  order?: 'asc' | 'desc'
  page?: number
  page_size?: number
}

// ── Error type ──────────────────────────────────────────────────────────────
export class ApiError extends Error {
  status: number
  body: unknown
  constructor(status: number, message: string, body?: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.body = body
  }
}

async function handle<T>(res: Response): Promise<T> {
  if (res.ok) {
    // 202 bodies (findings/report "still processing") are treated as errors by
    // callers that need a completed resource; here we only reach handle() for
    // endpoints where 2xx means a usable JSON body.
    if (res.status === 202) {
      const body = await res.json().catch(() => ({}))
      throw new ApiError(202, (body as { detail?: string }).detail || 'Not ready', body)
    }
    return (await res.json()) as T
  }
  let body: unknown = {}
  try {
    body = await res.json()
  } catch {
    body = {}
  }
  const detail =
    (body as { detail?: unknown }).detail ??
    (body as { message?: unknown }).message
  const message =
    typeof detail === 'string' && detail.length > 0 ? detail : `HTTP ${res.status}`
  throw new ApiError(res.status, message, body)
}

const jsonHeaders = { 'Content-Type': 'application/json' }

// ── Endpoints ───────────────────────────────────────────────────────────────
export async function submitScan(body: ScanRequestBody): Promise<ScanResponse> {
  const res = await fetch('/api/scan', {
    method: 'POST',
    headers: jsonHeaders,
    body: JSON.stringify(body),
  })
  // POST /api/scan returns 202 Accepted on success (the scan was created and
  // enqueued, or an existing duplicate is returned) — 202 here is NOT the
  // "resource not ready yet" meaning it has on /findings and /report, so it must
  // NOT go through handle()'s 202-throws path. Any 2xx carries a usable
  // ScanResponse body; only a non-2xx is a real error.
  if (res.ok) return (await res.json()) as ScanResponse
  let errBody: unknown = {}
  try {
    errBody = await res.json()
  } catch {
    errBody = {}
  }
  const detail =
    (errBody as { detail?: unknown }).detail ?? (errBody as { message?: unknown }).message
  const message =
    typeof detail === 'string' && detail.length > 0 ? detail : `HTTP ${res.status}`
  throw new ApiError(res.status, message, errBody)
}

export async function getScanModules(): Promise<ScanModuleInfo[]> {
  const res = await fetch('/api/scan/modules', { cache: 'no-store' })
  const data = await handle<{ modules: ScanModuleInfo[] }>(res)
  return data.modules ?? []
}

export async function getScans(params: ScanListParams = {}): Promise<ScanListResponse> {
  const qs = new URLSearchParams()
  if (params.status) qs.set('status', params.status)
  if (params.search) qs.set('search', params.search)
  if (params.sort) qs.set('sort', params.sort)
  if (params.order) qs.set('order', params.order)
  if (params.page) qs.set('page', String(params.page))
  if (params.page_size) qs.set('page_size', String(params.page_size))
  const res = await fetch(`/api/scans?${qs.toString()}`, { cache: 'no-store' })
  return handle<ScanListResponse>(res)
}

export async function getScanStatus(id: string): Promise<ScanStatusResponse> {
  const res = await fetch(`/api/scan/${id}/status`, { cache: 'no-store' })
  return handle<ScanStatusResponse>(res)
}

export async function postScanDecision(
  id: string,
  action: ScanDecisionAction,
): Promise<ScanStatusResponse> {
  const res = await fetch(`/api/scan/${id}/decision`, {
    method: 'POST',
    headers: jsonHeaders,
    body: JSON.stringify({ action }),
  })
  return handle<ScanStatusResponse>(res)
}

export async function getFindings(id: string): Promise<FindingsResponse> {
  const res = await fetch(`/api/scan/${id}/findings`, { cache: 'no-store' })
  return handle<FindingsResponse>(res)
}

export function reportPdfUrl(id: string): string {
  return `/api/scan/${id}/report`
}

// ── Hosted auth (only used by the private hosted frontend; backend gates it
//    behind REQUIRE_AUTH) ──────────────────────────────────────────────────
export interface OTPChallenge {
  email: string
  expires_in: number
  resend_in: number
}

export type AuthNextStep = 'verify_email' | 'verify_domain' | 'ready'

export interface AuthUser {
  id: string
  email: string
  email_verified: boolean
  has_verified_domain: boolean
  next_step: AuthNextStep
}

export interface DomainChallenge {
  verification_id: string
  domain: string
  method: 'meta_tag' | 'http_file'
  token: string
  meta_tag: string
  file_path: string
  file_contents: string
  instructions: string
}

export interface DomainCheckResult {
  verified: boolean
  domain: string
  claim_key?: string | null
  expires_at?: string | null
  detail?: string | null
}

// Cookies are same-origin (Next proxies /api/* to the backend), so credentials
// ride along; 'include' is belt-and-suspenders for any direct-origin setup.
const authInit: RequestInit = { credentials: 'include', cache: 'no-store' }

async function postJson<T>(url: string, body?: unknown): Promise<T> {
  const res = await fetch(url, {
    ...authInit,
    method: 'POST',
    headers: jsonHeaders,
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  return handle<T>(res)
}

export const signup = (email: string, password: string) =>
  postJson<OTPChallenge>('/api/auth/signup', { email, password })

export const verifyOtp = (email: string, code: string) =>
  postJson<AuthUser>('/api/auth/verify-otp', { email, code })

export const resendOtp = (email: string) =>
  postJson<OTPChallenge>('/api/auth/resend-otp', { email })

export const login = (email: string, password: string) =>
  postJson<AuthUser>('/api/auth/login', { email, password })

export const logout = () => postJson<{ ok: boolean }>('/api/auth/logout')

export async function getMe(): Promise<AuthUser | null> {
  const res = await fetch('/api/auth/me', authInit)
  if (res.status === 401) return null
  return handle<AuthUser>(res)
}

export const issueDomainChallenge = (domain: string, method: 'meta_tag' | 'http_file') =>
  postJson<DomainChallenge>('/api/verify/domain', { domain, method })

export const checkDomainChallenge = (verificationId: string) =>
  postJson<DomainCheckResult>(`/api/verify/domain/${verificationId}/check`)
