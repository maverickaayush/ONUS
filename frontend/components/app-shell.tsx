'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { Activity, FilePlus2, LayoutList } from 'lucide-react'

// GitHub mark inline (lucide dropped its brand icons); currentColor so it
// inherits the rail's cyan hover exactly like the nav icons.
function GithubMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" className={className} aria-hidden="true">
      <path d="M12 .5C5.37.5 0 5.87 0 12.5c0 5.3 3.44 9.8 8.21 11.39.6.11.82-.26.82-.58 0-.29-.01-1.05-.02-2.06-3.34.73-4.04-1.61-4.04-1.61-.55-1.39-1.34-1.76-1.34-1.76-1.09-.75.08-.73.08-.73 1.21.09 1.84 1.24 1.84 1.24 1.07 1.84 2.81 1.31 3.5 1 .11-.78.42-1.31.76-1.61-2.67-.3-5.47-1.34-5.47-5.95 0-1.31.47-2.39 1.24-3.23-.12-.31-.54-1.53.12-3.19 0 0 1.01-.32 3.3 1.23a11.5 11.5 0 0 1 6 0c2.29-1.55 3.3-1.23 3.3-1.23.66 1.66.24 2.88.12 3.19.77.84 1.24 1.92 1.24 3.23 0 4.62-2.81 5.64-5.49 5.94.43.37.81 1.1.81 2.22 0 1.6-.01 2.9-.01 3.29 0 .32.22.7.83.58C20.56 22.29 24 17.79 24 12.5 24 5.87 18.63.5 12 .5z" />
    </svg>
  )
}
import { AmbientBackground } from './ambient-background'
import { CommandPalette } from './command-palette'
import { OnusMark } from './ui'
import { cn } from '@/lib/format'

const NAV = [
  { href: '/', label: 'New Scan', icon: FilePlus2, match: (p: string) => p === '/' },
  // "Scan Status" is a placeholder destination - it resolves to a real status
  // page for a scan literally named `demo` (preserving the existing quirk).
  {
    href: '/scan/demo/status',
    label: 'Scan Status',
    icon: Activity,
    match: (p: string) => p.startsWith('/scan/'),
  },
  { href: '/scans', label: 'Scans', icon: LayoutList, match: (p: string) => p.startsWith('/scans') },
]

// Auth routes render full-bleed (their own TangleCanvas backdrop), without the
// command-center rail / ambient / grain overlays.
const AUTH_ROUTES = ['/sign-in', '/sign-up']

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  if (AUTH_ROUTES.some((r) => pathname === r || pathname.startsWith(r + '/'))) {
    return <>{children}</>
  }
  return (
    <>
      <AmbientBackground />
      <CommandPalette />
      {/* Film-grain texture - one root overlay, extreme low opacity, above
          everything but click-through. Felt, not seen: it just keeps large flat
          dark surfaces from reading as dead flat. */}
      <div
        aria-hidden
        className="pointer-events-none fixed inset-0 z-[100] opacity-[0.04]"
        style={{
          backgroundImage:
            "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='160' height='160'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='160' height='160' filter='url(%23n)'/%3E%3C/svg%3E\")",
          backgroundSize: '160px 160px',
        }}
      />
      <div className="flex min-h-screen">
        <nav
          aria-label="Primary"
          className="group onus-rail-in fixed inset-y-0 left-0 z-30 flex w-[64px] flex-col border-r border-line bg-panel/70 backdrop-blur-sm transition-[width] duration-200 hover:w-[208px]"
        >
          <Link
            href="/"
            className="flex h-16 shrink-0 items-center gap-3 overflow-hidden px-[19px]"
            aria-label="ONUS home"
          >
            <span className="relative shrink-0">
              <OnusMark className="onus-breathe h-[26px] w-[26px] text-accent" />
              {/* Systems-operational pip - the platform is alive and listening
                  before any scan runs. Reuses the "actively running" pulse, but
                  slow and calm, not urgent. */}
              <span className="absolute -bottom-0.5 -right-0.5 flex h-[7px] w-[7px]" title="Systems operational">
                <span
                  className="absolute inline-flex h-full w-full rounded-full bg-accent opacity-50"
                  style={{ animation: 'onus-pulse-ring 3s ease-out infinite' }}
                />
                <span className="relative inline-flex h-[7px] w-[7px] rounded-full bg-accent ring-2 ring-panel" />
              </span>
            </span>
            <span className="signage whitespace-nowrap text-[13px] font-bold text-ink text-glow-cyan opacity-0 transition-opacity duration-200 group-hover:opacity-100">
              ONUS
            </span>
          </Link>

          <ul className="flex flex-1 flex-col gap-1 px-2.5 pt-2">
            {NAV.map((item) => {
              const active = item.match(pathname)
              const Icon = item.icon
              return (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    className={cn(
                      'flex items-center gap-3.5 overflow-hidden rounded-md px-[11px] py-2.5 transition-colors',
                      active
                        ? 'bg-accent/12 text-accent'
                        : 'text-ink-dim hover:bg-white/[0.03] hover:text-ink',
                    )}
                    aria-current={active ? 'page' : undefined}
                  >
                    <Icon className="h-[18px] w-[18px] shrink-0" strokeWidth={1.7} />
                    <span className="whitespace-nowrap text-[13px] font-medium opacity-0 transition-opacity duration-200 group-hover:opacity-100">
                      {item.label}
                    </span>
                  </Link>
                </li>
              )
            })}
          </ul>

          <div className="overflow-hidden px-2.5 pb-4">
            <div className="flex items-center gap-3.5 rounded-md px-[11px] py-2 text-ink-faint">
              <kbd className="flex h-[18px] shrink-0 items-center rounded-xs border border-line-strong px-1 font-mono text-[10px]">
                ⌘K
              </kbd>
              <span className="whitespace-nowrap text-[11px] opacity-0 transition-opacity duration-200 group-hover:opacity-100">
                Command palette
              </span>
            </div>
            {/* Attribution - icon-only GitHub link, matching the nav icons above
                (same stroke, resting opacity, cyan hover). */}
            <a
              href="https://github.com/maverickaayush/ONUS"
              target="_blank"
              rel="noopener noreferrer"
              aria-label="ONUS on GitHub"
              title="ONUS on GitHub"
              className="mt-1 flex items-center rounded-md px-[11px] py-2 text-ink-dim transition-colors hover:bg-white/[0.03] hover:text-accent"
            >
              <GithubMark className="h-[18px] w-[18px] shrink-0" />
            </a>
          </div>
        </nav>

        {/* min-w-0: without it this flex child keeps min-width:auto and refuses
            to shrink below a wide descendant (the min-w-[920px] scans table /
            min-w-[720px] findings table), blowing the whole page out
            horizontally on narrow viewports. The tables scroll inside their own
            overflow-x-auto instead. */}
        <main className="ml-[64px] min-w-0 flex-1">{children}</main>
      </div>
    </>
  )
}
