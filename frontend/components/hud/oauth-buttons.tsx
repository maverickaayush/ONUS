'use client'

/**
 * OAuth entry buttons for the auth terminals. Renders "Continue with GitHub /
 * Google" (only for providers the backend reports as configured) + an OR
 * divider, in the ONUS HUD language — native, not third-party button styles.
 * Each is a full-page link to /api/auth/{provider}/login (server-side redirect
 * flow); the session cookie is set on the same-origin callback.
 */
import { useEffect, useState } from 'react'
import { getAuthProviders } from '@/lib/api'

function GithubIcon() {
  return (
    <svg viewBox="0 0 24 24" width="15" height="15" fill="currentColor" aria-hidden="true">
      <path d="M12 .5C5.37.5 0 5.87 0 12.5c0 5.3 3.44 9.8 8.21 11.39.6.11.82-.26.82-.58 0-.29-.01-1.05-.02-2.06-3.34.73-4.04-1.61-4.04-1.61-.55-1.39-1.34-1.76-1.34-1.76-1.09-.75.08-.73.08-.73 1.21.09 1.84 1.24 1.84 1.24 1.07 1.84 2.81 1.31 3.5 1 .11-.78.42-1.31.76-1.61-2.67-.3-5.47-1.34-5.47-5.95 0-1.31.47-2.39 1.24-3.23-.12-.31-.54-1.53.12-3.19 0 0 1.01-.32 3.3 1.23a11.5 11.5 0 0 1 6 0c2.29-1.55 3.3-1.23 3.3-1.23.66 1.66.24 2.88.12 3.19.77.84 1.24 1.92 1.24 3.23 0 4.62-2.81 5.64-5.49 5.94.43.37.81 1.1.81 2.22 0 1.6-.01 2.9-.01 3.29 0 .32.22.7.83.58C20.56 22.29 24 17.79 24 12.5 24 5.87 18.63.5 12 .5z" />
    </svg>
  )
}

function GoogleIcon() {
  // Mono "G" glyph, tinted by currentColor to stay native to the HUD.
  return (
    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
      <path d="M21 12.2c0 5-3.6 8.3-8.8 8.3A8.5 8.5 0 1 1 18 5.9" strokeLinecap="round" />
      <path d="M21 12.2h-8.2" strokeLinecap="round" />
    </svg>
  )
}

export function OAuthButtons() {
  const [p, setP] = useState<{ google: boolean; github: boolean }>({ google: false, github: false })
  useEffect(() => { getAuthProviders().then((r) => setP({ google: r.google, github: r.github })).catch(() => {}) }, [])
  if (!p.google && !p.github) return null

  return (
    <div className="mb-5">
      {/* Order: Google, then GitHub, then (below the divider) email + password. */}
      {p.google && (
        <a href="/api/auth/google/login" className="onus-oauth-btn mb-2.5 flex w-full items-center justify-center gap-2.5 rounded-[6px] py-3 text-[13.5px] font-semibold">
          <GoogleIcon /> Continue with Google
        </a>
      )}
      {p.github && (
        <a href="/api/auth/github/login" className="onus-oauth-btn mb-2.5 flex w-full items-center justify-center gap-2.5 rounded-[6px] py-3 text-[13.5px] font-semibold">
          <GithubIcon /> Continue with GitHub
        </a>
      )}
      <div className="my-4 flex items-center gap-3">
        <span className="h-px flex-1 bg-border" />
        <span className="text-[12px] font-medium text-ink-faint">or</span>
        <span className="h-px flex-1 bg-border" />
      </div>
    </div>
  )
}
