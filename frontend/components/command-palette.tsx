'use client'

import { useEffect, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import { ArrowRight, CornerDownLeft, FilePlus2, LayoutList, Radar, Search } from 'lucide-react'
import { cn } from '@/lib/format'
import { OnusMark } from './ui'

interface Action {
  id: string
  label: string
  hint: string
  icon: React.ComponentType<{ className?: string; strokeWidth?: number }>
  run: (router: ReturnType<typeof useRouter>) => void
}

const STATIC_ACTIONS: Action[] = [
  {
    id: 'new',
    label: 'New Scan',
    hint: 'Start a new assessment',
    icon: FilePlus2,
    run: (r) => r.push('/scan/new'),
  },
  {
    id: 'scans',
    label: 'Scans',
    hint: 'Open the scan ledger',
    icon: LayoutList,
    run: (r) => r.push('/scans'),
  },
]

// A UUID-ish token - enough to treat the query as a job id and jump straight
// to its status page (client-side navigation only, no backend call).
const IDLIKE = /^[0-9a-fA-F-]{8,}$/

export function CommandPalette() {
  const router = useRouter()
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setOpen((v) => !v)
      }
      if (e.key === 'Escape') setOpen(false)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  useEffect(() => {
    if (!open) {
      setQuery('')
      setActive(0)
    }
  }, [open])

  const results = useMemo<Action[]>(() => {
    const q = query.trim()
    const base = STATIC_ACTIONS.filter((a) =>
      a.label.toLowerCase().includes(q.toLowerCase()),
    )
    if (IDLIKE.test(q)) {
      base.unshift({
        id: 'goto',
        label: `Go to scan ${q.slice(0, 12)}${q.length > 12 ? '…' : ''}`,
        hint: 'Open scan status',
        icon: Radar,
        run: (r) => r.push(`/scan/${q}/status`),
      })
    }
    return base
  }, [query])

  useEffect(() => {
    if (active >= results.length) setActive(0)
  }, [results.length, active])

  if (!open) return null

  const choose = (a: Action) => {
    setOpen(false)
    a.run(router)
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center px-4 pt-[14vh]"
      role="dialog"
      aria-modal="true"
      aria-label="Command palette"
    >
      <div
        className="absolute inset-0 bg-black/55 backdrop-blur-[2px]"
        onClick={() => setOpen(false)}
      />
      <div className="glass relative w-full max-w-[560px] overflow-hidden rounded-[4px] onus-fade-up">
        <div className="flex items-center gap-3 border-b border-line px-4">
          <Search className="h-4 w-4 text-ink-faint" strokeWidth={1.6} />
          <input
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            role="combobox"
            aria-expanded="true"
            aria-controls="cmdk-list"
            aria-autocomplete="list"
            aria-activedescendant={results[active] ? `cmdk-opt-${results[active].id}` : undefined}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') {
                e.preventDefault()
                setActive((i) => Math.min(results.length - 1, i + 1))
              } else if (e.key === 'ArrowUp') {
                e.preventDefault()
                setActive((i) => Math.max(0, i - 1))
              } else if (e.key === 'Enter' && results[active]) {
                choose(results[active])
              }
            }}
            placeholder="Jump to a page, or paste a job ID…"
            className="w-full bg-transparent py-3.5 text-[14px] text-ink placeholder:text-ink-faint focus:outline-none"
          />
        </div>
        <ul id="cmdk-list" role="listbox" aria-label="Commands" className="max-h-[320px] overflow-y-auto p-1.5">
          {results.length === 0 && (
            <li className="px-3 py-6 text-center text-[13px] text-ink-faint">No matches.</li>
          )}
          {results.map((a, i) => {
            const Icon = a.icon
            return (
              <li key={a.id} id={`cmdk-opt-${a.id}`} role="option" aria-selected={i === active}>
                <button
                  tabIndex={-1}
                  onMouseEnter={() => setActive(i)}
                  onClick={() => choose(a)}
                  className={cn(
                    'flex w-full items-center gap-3 rounded-md px-3 py-2.5 text-left',
                    i === active ? 'bg-accent/15' : 'hover:bg-white/[0.03]',
                  )}
                >
                  <Icon className={cn('h-4 w-4', i === active ? 'text-accent' : 'text-ink-dim')} strokeWidth={1.6} />
                  <span className="flex-1">
                    <span className="block text-[13px] font-medium text-ink">{a.label}</span>
                    <span className="block text-[11px] text-ink-faint">{a.hint}</span>
                  </span>
                  {i === active ? (
                    <CornerDownLeft className="h-3.5 w-3.5 text-ink-faint" strokeWidth={1.6} />
                  ) : (
                    <ArrowRight className="h-3.5 w-3.5 text-ink-faint/50" strokeWidth={1.6} />
                  )}
                </button>
              </li>
            )
          })}
        </ul>
        {/* Emblem placement (2 of 4): quiet identity anchor in the palette's own
            surface, paired with the keyboard legend. */}
        <div className="flex items-center justify-between border-t border-line px-4 py-2.5 text-ink-faint">
          <span className="flex items-center gap-2">
            <OnusMark className="h-3.5 w-3.5 text-ink-faint" />
            <span className="text-[11px] font-medium tracking-[0.18em]">ONUS</span>
          </span>
          <span className="flex items-center gap-3 font-mono text-[10.5px]">
            <span>↑↓ navigate</span>
            <span>↵ open</span>
            <span>esc close</span>
          </span>
        </div>
      </div>
    </div>
  )
}
