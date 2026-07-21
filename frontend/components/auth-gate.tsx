'use client'

/**
 * Frontend authentication guard for the hosted tier. The BACKEND is the source
 * of truth - we call GET /api/auth/me and never re-implement auth logic here.
 *
 * Public routes render immediately. Every other route is guarded, so new
 * authenticated pages are protected by default:
 *   - checking  -> full-screen loading (NO app chrome, so protected UI never flashes)
 *   - 200 (user)-> render the app
 *   - 401 (null)-> redirect to /sign-in?next=<path>
 *   - network/server error -> a real error screen with Retry (no redirect loop)
 *
 * Anonymous users hitting an unknown URL are sent to sign-in (standard SaaS);
 * authenticated users still get the real 404 (getMe 200 -> children render).
 */
import { useEffect, useState } from 'react'
import { usePathname, useRouter } from 'next/navigation'
import { getAuthProviders, getMe } from '@/lib/api'
import { AppShell } from './app-shell'
import { OnusMark } from './ui'

// '/' is the marketing landing and must render for anonymous visitors. Exact
// match only: isPublic()'s prefix arm tests startsWith('//'), which no real
// path satisfies, so this opens the root and nothing beneath it.
const PUBLIC = ['/', '/sign-in', '/sign-up', '/privacy', '/terms']
const isPublic = (p: string) => PUBLIC.some((r) => p === r || p.startsWith(r + '/'))

type Phase = 'checking' | 'authed' | 'error'

export function AuthGate({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  const router = useRouter()
  const guarded = !isPublic(pathname)
  const [phase, setPhase] = useState<Phase>('checking')

  useEffect(() => {
    if (!guarded) return
    let cancelled = false
    setPhase('checking')
    // Self-hosted (REQUIRE_AUTH=false) has no accounts at all: guarding routes
    // there would put a sign-in wall in front of a single-operator local
    // instance, which is exactly what `docker compose up` must not do.
    getAuthProviders()
      .then((p) => {
        if (cancelled) return null
        if (!p.require_auth) {
          setPhase('authed')
          return null
        }
        return getMe()
      })
      .then((user) => {
        if (cancelled || user === null) return // null = self-hosted short-circuit above
        if (user) setPhase('authed')
        // Not authenticated: preserve the intended destination.
        else router.replace(`/sign-in?next=${encodeURIComponent(pathname)}`)
      })
      .catch(() => {
        // Network / server failure - show an error, do NOT redirect (a redirect
        // here could loop if /sign-in's own check also fails).
        if (!cancelled) setPhase('error')
      })
    return () => {
      cancelled = true
    }
  }, [pathname, guarded, router])

  // Public routes never block on an auth check.
  if (!guarded) return <AppShell>{children}</AppShell>
  if (phase === 'error') return <AuthErrorScreen />
  if (phase !== 'authed') return <AuthLoadingScreen />
  return <AppShell>{children}</AppShell>
}

function AuthLoadingScreen() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-canvas">
      <OnusMark className="onus-breathe h-10 w-10 text-accent" />
      <p className="signage text-[11px] text-ink-dim">Authenticating…</p>
    </div>
  )
}

function AuthErrorScreen() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-canvas px-6 text-center">
      <OnusMark className="h-10 w-10 text-ink-faint" />
      <p className="display text-[28px] text-ink">Unable to verify your session.</p>
      <p className="max-w-sm text-[13px] leading-relaxed text-ink-dim">
        The authentication service is unreachable. Check your connection and try again.
      </p>
      <button
        onClick={() => window.location.reload()}
        className="press mt-2 rounded-[6px] border-2 border-border bg-lime px-4 py-2 text-[12px] font-bold text-ink"
        style={{ boxShadow: 'var(--shadow-hard)' }}
      >
        Retry
      </button>
    </div>
  )
}
