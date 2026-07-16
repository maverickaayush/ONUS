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
import { getMe } from '@/lib/api'
import { AppShell } from './app-shell'
import { OnusMark } from './ui'

const PUBLIC = ['/sign-in', '/sign-up', '/privacy', '/terms']
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
    getMe()
      .then((user) => {
        if (cancelled) return
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
    <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-[#030304]">
      <OnusMark className="onus-breathe h-10 w-10 text-accent" />
      <p className="font-mono text-[11px] uppercase tracking-[0.3em] text-white/40">Authenticating…</p>
    </div>
  )
}

function AuthErrorScreen() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-[#030304] px-6 text-center">
      <OnusMark className="h-10 w-10 text-white/25" />
      <p className="font-mono text-[13px] text-white">Unable to verify your session.</p>
      <p className="max-w-sm text-[12px] leading-relaxed text-white/40">
        The authentication service is unreachable. Check your connection and try again.
      </p>
      <button
        onClick={() => window.location.reload()}
        className="mt-2 rounded-md border border-white/15 px-4 py-2 font-mono text-[11px] uppercase tracking-[0.14em] text-white/70 transition-colors hover:bg-white/[0.05]"
      >
        Retry
      </button>
    </div>
  )
}
