"use client"

import { useState, useEffect } from "react"
import { useRouter } from "next/navigation"
import { cn } from "@/lib/utils"
import { VaptBackground } from "@/components/vapt/background"
import { submitScan, getScanModules, ApiError } from "@/lib/api"
import type { ScanModuleInfo, AuthConfig } from "@/lib/api"

function isValidDomain(value: string) {
  return /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(
    value.trim(),
  )
}

// Keyed by the backend's icon_hint (a semantic category, not a specific
// module id) - source of truth for which modules exist is GET
// /api/scan/modules (tasks/base_task.py's SCAN_MODULES on the backend), not
// a hardcoded list here. A hint this map doesn't recognize yet (e.g. a
// brand-new module added on the backend before a bespoke icon exists for
// it) falls back to GENERIC_ICON so a 9th module still renders a badge,
// just with a plain icon.
const MODULE_ICONS: Record<string, React.ReactNode> = {
  network: (
    <svg viewBox="0 0 20 20" fill="currentColor" className="h-3.5 w-3.5" aria-hidden="true">
      <path d="M9 9a2 2 0 114 0 2 2 0 01-4 0z" />
      <path
        fillRule="evenodd"
        d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-13a4 4 0 00-3.446 6.032l-2.261 2.26a1 1 0 101.414 1.415l2.261-2.261A4 4 0 1011 5z"
        clipRule="evenodd"
      />
    </svg>
  ),
  web: (
    <svg viewBox="0 0 20 20" fill="currentColor" className="h-3.5 w-3.5" aria-hidden="true">
      <path
        fillRule="evenodd"
        d="M4.083 9h1.946c.089-1.546.383-2.97.837-4.118A6.004 6.004 0 004.083 9zM10 2a8 8 0 100 16A8 8 0 0010 2zm0 2c-.076 0-.232.032-.465.262-.238.234-.497.623-.737 1.182-.389.907-.673 2.142-.766 3.556h3.936c-.093-1.414-.377-2.649-.766-3.556-.24-.56-.5-.948-.737-1.182C10.232 4.032 10.076 4 10 4zm3.971 5c-.089-1.546-.383-2.97-.837-4.118A6.004 6.004 0 0115.917 9h-1.946zm-2.003 2H8.032c.093 1.414.377 2.649.766 3.556.24.56.5.948.737 1.182.233.23.389.262.465.262.076 0 .232-.032.465-.262.238-.234.498-.623.737-1.182.389-.907.673-2.142.766-3.556zm1.166 4.118c.454-1.147.748-2.572.837-4.118h1.946a6.004 6.004 0 01-2.783 4.118zm-6.268 0C6.412 13.97 6.118 12.546 6.03 11H4.083a6.004 6.004 0 002.783 4.118z"
        clipRule="evenodd"
      />
    </svg>
  ),
  lock: (
    <svg viewBox="0 0 20 20" fill="currentColor" className="h-3.5 w-3.5" aria-hidden="true">
      <path
        fillRule="evenodd"
        d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z"
        clipRule="evenodd"
      />
    </svg>
  ),
  list: (
    <svg viewBox="0 0 20 20" fill="currentColor" className="h-3.5 w-3.5" aria-hidden="true">
      <path
        fillRule="evenodd"
        d="M3 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h8a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h6a1 1 0 110 2H4a1 1 0 01-1-1z"
        clipRule="evenodd"
      />
    </svg>
  ),
  alert: (
    <svg viewBox="0 0 20 20" fill="currentColor" className="h-3.5 w-3.5" aria-hidden="true">
      <path
        fillRule="evenodd"
        d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z"
        clipRule="evenodd"
      />
    </svg>
  ),
  fingerprint: (
    <svg viewBox="0 0 20 20" fill="currentColor" className="h-3.5 w-3.5" aria-hidden="true">
      <path fillRule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clipRule="evenodd" />
    </svg>
  ),
  target: (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" className="h-3.5 w-3.5" aria-hidden="true">
      <circle cx="10" cy="10" r="7" />
      <circle cx="10" cy="10" r="3.5" />
      <circle cx="10" cy="10" r="0.5" fill="currentColor" stroke="none" />
    </svg>
  ),
  folder: (
    <svg viewBox="0 0 20 20" fill="currentColor" className="h-3.5 w-3.5" aria-hidden="true">
      <path d="M2 6a2 2 0 012-2h4.586a1 1 0 01.707.293L10.414 5H16a2 2 0 012 2v7a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
    </svg>
  ),
}

const GENERIC_ICON = (
  <svg viewBox="0 0 20 20" fill="currentColor" className="h-3.5 w-3.5" aria-hidden="true">
    <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
  </svg>
)

export function HomeForm() {
  const router = useRouter()
  const [domain, setDomain] = useState("")
  const [authorized, setAuthorized] = useState(false)
  const [touched, setTouched] = useState(false)
  const [loading, setLoading] = useState(false)
  const [accordionOpen, setAccordionOpen] = useState(false)
  const [submitError, setSubmitError] = useState("")
  const [modules, setModules] = useState<ScanModuleInfo[]>([])

  // Authenticated scan (optional) - off by default; only sent to the
  // backend when all three fields are filled in (see handleSubmit below).
  const [authAccordionOpen, setAuthAccordionOpen] = useState(false)
  const [authLoginUrl, setAuthLoginUrl] = useState("")
  const [authUsername, setAuthUsername] = useState("")
  const [authPassword, setAuthPassword] = useState("")
  const [authLoginType, setAuthLoginType] = useState<"auto" | "form" | "json">("auto")
  const [authUsernameField, setAuthUsernameField] = useState("")
  const [authPasswordField, setAuthPasswordField] = useState("")
  const [authTokenJsonPath, setAuthTokenJsonPath] = useState("")

  useEffect(() => {
    getScanModules()
      .then(setModules)
      .catch(() => {
        // Decorative sections (badges/accordion) - fail silently rather
        // than block the actual scan-submission form on this fetch.
      })
  }, [])

  const valid = isValidDomain(domain)
  const canSubmit = valid && authorized

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!canSubmit) return
    setLoading(true)
    setSubmitError("")
    // Only sent when all three required fields are filled in - an empty
    // Login URL/Username/Password means "not using authenticated scanning",
    // no separate enable/disable toggle needed.
    const auth: AuthConfig | undefined =
      authLoginUrl.trim() && authUsername && authPassword
        ? {
            loginUrl: authLoginUrl.trim(),
            username: authUsername,
            password: authPassword,
            loginType: authLoginType,
            ...(authUsernameField.trim() && { usernameField: authUsernameField.trim() }),
            ...(authPasswordField.trim() && { passwordField: authPasswordField.trim() }),
            ...(authLoginType === "json" &&
              authTokenJsonPath.trim() && { tokenJsonPath: authTokenJsonPath.trim() }),
          }
        : undefined
    try {
      const response = await submitScan(domain.trim(), authorized, auth)
      router.push(`/scan/${response.job_id}/status`)
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 403) {
          setSubmitError("Authorization confirmation required - check the box to confirm you are authorized.")
        } else if (err.status === 409) {
          // Duplicate scan - extract existing job_id and redirect
          try {
            const detail = JSON.parse(err.message)
            if (detail?.job_id) {
              router.push(`/scan/${detail.job_id}/status`)
              return
            }
          } catch {
            // message wasn't JSON, fall through to generic error
          }
          setSubmitError(err.message)
        } else {
          setSubmitError(err.message || "Submission failed. Please try again.")
        }
      } else {
        setSubmitError("Cannot reach scan server. Is the backend running?")
      }
      setLoading(false)
    }
  }

  return (
    <main className="vapt-noise relative min-h-[calc(100vh-56px)] flex items-center justify-center px-4 py-12 overflow-hidden">
      <VaptBackground />

      <div className="relative z-10 w-full max-w-xl">
        {/* Hero */}
        <div
          className="text-center mb-8 vapt-fade-up"
          style={{ animationDelay: "60ms" }}
        >
          <span className="inline-flex items-center gap-2 px-3 py-1 rounded-full backdrop-blur-sm bg-white/5 border border-blue-500/30 text-xs font-medium text-blue-300 tracking-wide mb-6">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-3.5 w-3.5" aria-hidden="true">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            IIT Kanpur Computer Centre
          </span>
          <h1 className="text-4xl sm:text-5xl font-bold tracking-tight text-balance bg-gradient-to-r from-slate-100 via-blue-200 to-slate-100 bg-clip-text text-transparent leading-tight">
            Automated Vulnerability
            <br />
            Assessment Platform
          </h1>
          <p className="mt-4 text-slate-400 text-base leading-relaxed max-w-md mx-auto">
            Scan any authorized domain and receive a professional security
            report in minutes.
          </p>
        </div>

        {/* Form card */}
        <div
          className="vapt-fade-up backdrop-blur-md bg-white/5 border border-white/10 rounded-3xl p-8 shadow-2xl"
          style={{ animationDelay: "200ms" }}
        >
          <form onSubmit={handleSubmit} noValidate>
            {/* Domain Input */}
            <div className="mb-5">
              <label
                htmlFor="domain"
                className="block text-xs font-medium uppercase tracking-wide text-slate-400 mb-2"
              >
                Target Domain
              </label>
              <div className="relative">
                <input
                  id="domain"
                  type="text"
                  autoComplete="off"
                  spellCheck={false}
                  value={domain}
                  onChange={(e) => {
                    setDomain(e.target.value)
                    setTouched(true)
                  }}
                  placeholder="Enter target domain e.g. example.com"
                  className={cn(
                    "w-full px-4 py-3 pr-10 rounded-xl bg-white/5 border text-slate-100 placeholder:text-slate-600 text-sm focus:outline-none focus:ring-2 transition-all",
                    touched && domain && !valid
                      ? "border-red-500/50 focus:border-red-500/60 focus:ring-red-500/20 shadow-[0_0_18px_-4px_rgba(239,68,68,0.4)]"
                      : touched && valid
                        ? "border-emerald-500/50 focus:border-emerald-500/60 focus:ring-emerald-500/20 shadow-[0_0_18px_-4px_rgba(16,185,129,0.4)]"
                        : "border-white/10 focus:border-blue-500/60 focus:ring-blue-500/20 focus:bg-white/[0.07]",
                  )}
                  aria-describedby={
                    touched && domain && !valid ? "domain-error" : undefined
                  }
                  aria-invalid={touched && domain ? !valid : undefined}
                />
                {touched && domain && (
                  <span className="absolute right-3 top-1/2 -translate-y-1/2">
                    {valid ? (
                      <svg
                        className="h-5 w-5 text-emerald-400"
                        viewBox="0 0 20 20"
                        fill="currentColor"
                        aria-hidden="true"
                      >
                        <path
                          fillRule="evenodd"
                          d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
                          clipRule="evenodd"
                        />
                      </svg>
                    ) : (
                      <svg
                        className="h-5 w-5 text-red-400"
                        viewBox="0 0 20 20"
                        fill="currentColor"
                        aria-hidden="true"
                      >
                        <path
                          fillRule="evenodd"
                          d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z"
                          clipRule="evenodd"
                        />
                      </svg>
                    )}
                  </span>
                )}
              </div>
              {touched && domain && !valid && (
                <p id="domain-error" className="mt-2 text-xs text-red-400" role="alert">
                  Please enter a valid domain name (e.g. example.com or sub.example.org)
                </p>
              )}
            </div>

            {/* Authorization checkbox */}
            <div className="mb-6 p-4 rounded-2xl bg-amber-500/10 border border-amber-500/20">
              <label className="flex items-start gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={authorized}
                  onChange={(e) => setAuthorized(e.target.checked)}
                  className="mt-0.5 h-4 w-4 rounded border-amber-500/40 bg-transparent text-blue-500 focus:ring-blue-500/40 cursor-pointer accent-blue-500"
                  aria-label="Authorization confirmation"
                />
                <span className="flex items-start gap-1.5 text-sm text-amber-200/90">
                  <svg
                    className="h-4 w-4 text-amber-400 mt-0.5 flex-shrink-0"
                    viewBox="0 0 20 20"
                    fill="currentColor"
                    aria-hidden="true"
                  >
                    <path
                      fillRule="evenodd"
                      d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z"
                      clipRule="evenodd"
                    />
                  </svg>
                  <span>
                    <span className="font-semibold text-amber-100">I confirm</span> I am
                    authorized to perform security testing on this domain.
                    Unauthorized scanning may violate applicable laws.
                  </span>
                </span>
              </label>
            </div>

            {/* Authenticated scan (optional) - moved inside the form, before
                Submit, and directly under the fields it actually affects.
                Real UX gap found live: this used to live in its own
                accordion card below the Submit button, visually separate
                from the form - a user filling in login credentials had to
                scroll back up to find Submit, and the button looked
                "ready" without ever noticing the auth section existed. */}
            <div className="mb-6 border border-white/10 rounded-2xl overflow-hidden">
              <button
                type="button"
                onClick={() => setAuthAccordionOpen((o) => !o)}
                className="w-full flex items-center justify-between px-4 py-3 text-sm font-medium text-slate-300 hover:bg-white/5 transition-colors"
                aria-expanded={authAccordionOpen}
              >
                <span>Authenticated scan (optional) - fill in before starting if the target needs a login</span>
                <svg
                  className={cn(
                    "h-4 w-4 text-slate-500 transition-transform flex-shrink-0 ml-2",
                    authAccordionOpen && "rotate-180",
                  )}
                  viewBox="0 0 20 20"
                  fill="currentColor"
                  aria-hidden="true"
                >
                  <path
                    fillRule="evenodd"
                    d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z"
                    clipRule="evenodd"
                  />
                </svg>
              </button>
              {authAccordionOpen && (
                <div className="px-4 pb-4 pt-1 border-t border-white/8 space-y-3">
                  <p className="text-xs text-slate-500">
                    If the target sits behind a login, provide credentials so the
                    scan can log in first - otherwise only the unauthenticated
                    surface is reachable. Leave blank to skip, then press
                    Start Scan below.
                  </p>
                  <div>
                    <span className="block text-xs font-medium uppercase tracking-wide text-slate-400 mb-1.5">
                      Login type
                    </span>
                    <div className="inline-flex rounded-lg border border-white/10 overflow-hidden text-sm">
                      {(["auto", "form", "json"] as const).map((t) => (
                        <button
                          key={t}
                          type="button"
                          onClick={() => setAuthLoginType(t)}
                          className={cn(
                            "px-4 py-1.5 transition-colors",
                            authLoginType === t
                              ? "bg-blue-500/80 text-white"
                              : "bg-white/5 text-slate-400 hover:text-slate-200",
                          )}
                        >
                          {t === "auto" ? "Auto-detect" : t === "form" ? "Form" : "JSON API"}
                        </button>
                      ))}
                    </div>
                    <p className="text-xs text-slate-500 mt-1.5">
                      {authLoginType === "auto"
                        ? "Sniffs the login URL for you - HTML form vs JSON API. Just fill in URL + username + password."
                        : authLoginType === "form"
                          ? "Standard HTML login form (application/x-www-form-urlencoded)."
                          : "JSON login (modern SPAs, e.g. a REST /login endpoint returning a bearer token)."}
                    </p>
                  </div>
                  <div>
                    <label htmlFor="auth-login-url" className="block text-xs font-medium uppercase tracking-wide text-slate-400 mb-1.5">
                      Login URL
                    </label>
                    <input
                      id="auth-login-url"
                      type="text"
                      autoComplete="off"
                      spellCheck={false}
                      value={authLoginUrl}
                      onChange={(e) => setAuthLoginUrl(e.target.value)}
                      placeholder="https://example.com/login.php"
                      className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-slate-100 placeholder:text-slate-600 text-sm focus:outline-none focus:ring-2 focus:border-blue-500/60 focus:ring-blue-500/20"
                    />
                  </div>
                  <div>
                    <label htmlFor="auth-username" className="block text-xs font-medium uppercase tracking-wide text-slate-400 mb-1.5">
                      Username
                    </label>
                    <input
                      id="auth-username"
                      type="text"
                      autoComplete="off"
                      spellCheck={false}
                      value={authUsername}
                      onChange={(e) => setAuthUsername(e.target.value)}
                      className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-slate-100 placeholder:text-slate-600 text-sm focus:outline-none focus:ring-2 focus:border-blue-500/60 focus:ring-blue-500/20"
                    />
                  </div>
                  <div>
                    <label htmlFor="auth-password" className="block text-xs font-medium uppercase tracking-wide text-slate-400 mb-1.5">
                      Password
                    </label>
                    <input
                      id="auth-password"
                      type="password"
                      autoComplete="off"
                      value={authPassword}
                      onChange={(e) => setAuthPassword(e.target.value)}
                      className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-slate-100 placeholder:text-slate-600 text-sm focus:outline-none focus:ring-2 focus:border-blue-500/60 focus:ring-blue-500/20"
                    />
                  </div>
                  {/* Optional field-name overrides + JSON token path */}
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label htmlFor="auth-user-field" className="block text-xs font-medium uppercase tracking-wide text-slate-400 mb-1.5">
                        Username field
                      </label>
                      <input
                        id="auth-user-field"
                        type="text"
                        autoComplete="off"
                        spellCheck={false}
                        value={authUsernameField}
                        onChange={(e) => setAuthUsernameField(e.target.value)}
                        placeholder={authLoginType === "json" ? "email" : "username"}
                        className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-slate-100 placeholder:text-slate-600 text-sm focus:outline-none focus:ring-2 focus:border-blue-500/60 focus:ring-blue-500/20"
                      />
                    </div>
                    <div>
                      <label htmlFor="auth-pass-field" className="block text-xs font-medium uppercase tracking-wide text-slate-400 mb-1.5">
                        Password field
                      </label>
                      <input
                        id="auth-pass-field"
                        type="text"
                        autoComplete="off"
                        spellCheck={false}
                        value={authPasswordField}
                        onChange={(e) => setAuthPasswordField(e.target.value)}
                        placeholder="password"
                        className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-slate-100 placeholder:text-slate-600 text-sm focus:outline-none focus:ring-2 focus:border-blue-500/60 focus:ring-blue-500/20"
                      />
                    </div>
                  </div>
                  {authLoginType === "json" && (
                    <div>
                      <label htmlFor="auth-token-path" className="block text-xs font-medium uppercase tracking-wide text-slate-400 mb-1.5">
                        Token JSON path
                      </label>
                      <input
                        id="auth-token-path"
                        type="text"
                        autoComplete="off"
                        spellCheck={false}
                        value={authTokenJsonPath}
                        onChange={(e) => setAuthTokenJsonPath(e.target.value)}
                        placeholder="authentication.token"
                        className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-slate-100 placeholder:text-slate-600 text-sm focus:outline-none focus:ring-2 focus:border-blue-500/60 focus:ring-blue-500/20"
                      />
                      <p className="text-xs text-slate-500 mt-1.5">
                        Dot-path to the bearer token in the login response, sent as
                        <span className="text-slate-400"> Authorization: Bearer &lt;token&gt;</span> on every request.
                      </p>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Submission error */}
            {submitError && (
              <div className="mb-4 px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-300 text-sm" role="alert">
                {submitError}
              </div>
            )}

            {/* Submit button */}
            <button
              type="submit"
              disabled={!canSubmit || loading}
              className={cn(
                "w-full flex items-center justify-center gap-2 py-3 rounded-xl text-sm font-semibold transition-all",
                canSubmit && !loading
                  ? "bg-gradient-to-r from-blue-600 to-blue-500 text-white shadow-lg shadow-blue-500/25 hover:shadow-blue-500/40 hover:brightness-110"
                  : "bg-white/5 border border-white/8 text-slate-600 cursor-not-allowed",
              )}
            >
              {loading ? (
                <>
                  <svg
                    className="animate-spin h-4 w-4"
                    viewBox="0 0 24 24"
                    fill="none"
                    aria-hidden="true"
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
                  Initiating scan...
                </>
              ) : (
                <>
                  <svg
                    className="h-4 w-4"
                    viewBox="0 0 20 20"
                    fill="currentColor"
                    aria-hidden="true"
                  >
                    <path
                      fillRule="evenodd"
                      d="M10 18a8 8 0 100-16 8 8 0 000 16zM9.555 7.168A1 1 0 008 8v4a1 1 0 001.555.832l3-2a1 1 0 000-1.664l-3-2z"
                      clipRule="evenodd"
                    />
                  </svg>
                  Start Scan
                </>
              )}
            </button>
          </form>
        </div>

        {/* Module pills - sourced from GET /api/scan/modules, not a
            hardcoded list, so a module added on the backend shows up here
            without a frontend code change. */}
        {modules.length > 0 && (
          <div className="mt-6 flex flex-wrap items-center justify-center gap-2">
            <span className="text-xs text-slate-500 mr-1 font-medium">Covers:</span>
            {modules.map((m, i) => (
              <span
                key={m.id}
                className="vapt-fade-up inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full backdrop-blur-sm bg-white/5 border border-white/10 text-xs font-medium text-slate-300 hover:border-blue-500/40 hover:bg-blue-500/10 hover:text-blue-200 transition-all duration-200"
                style={{ animationDelay: `${300 + i * 50}ms` }}
              >
                <span className="text-slate-500">{MODULE_ICONS[m.icon_hint] ?? GENERIC_ICON}</span>
                {m.label}
              </span>
            ))}
          </div>
        )}

        {/* Expandable accordion */}
        <div
          className="vapt-fade-up mt-4 border border-white/10 rounded-2xl backdrop-blur-sm bg-white/5 overflow-hidden"
          style={{ animationDelay: "560ms" }}
        >
          <button
            type="button"
            onClick={() => setAccordionOpen((o) => !o)}
            className="w-full flex items-center justify-between px-4 py-3 text-sm font-medium text-slate-300 hover:bg-white/5 transition-colors"
            aria-expanded={accordionOpen}
          >
            <span>What does this scan check?</span>
            <svg
              className={cn(
                "h-4 w-4 text-slate-500 transition-transform",
                accordionOpen && "rotate-180",
              )}
              viewBox="0 0 20 20"
              fill="currentColor"
              aria-hidden="true"
            >
              <path
                fillRule="evenodd"
                d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z"
                clipRule="evenodd"
              />
            </svg>
          </button>
          {accordionOpen && (
            <div className="px-4 pb-4 pt-1 border-t border-white/8">
              <ul className="space-y-2.5">
                {modules.map((m, i) => (
                  <li key={m.id} className="text-sm">
                    <span className="font-semibold text-slate-200">{i + 1}. {m.label}:</span>{" "}
                    <span className="text-slate-400">{m.description}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

      </div>
    </main>
  )
}
