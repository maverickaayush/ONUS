'use client'

import { useEffect, useRef, useState } from 'react'
import { AlertTriangle, Ban, Play, RotateCcw } from 'lucide-react'
import type { ScanDecisionAction } from '@/lib/api'
import { cn } from '@/lib/format'
import { Spinner } from './ui'

export function DecisionModal({
  moduleErrors,
  canRetry,
  labelFor,
  onDecide,
}: {
  moduleErrors: Record<string, string>
  canRetry: boolean
  labelFor: (id: string) => string
  onDecide: (action: ScanDecisionAction) => Promise<void>
}) {
  const [pending, setPending] = useState<ScanDecisionAction | null>(null)
  const busy = pending !== null

  const dialogRef = useRef<HTMLDivElement>(null)
  const cancelRef = useRef<HTMLButtonElement>(null)
  const retryRef = useRef<HTMLButtonElement>(null)
  const continueRef = useRef<HTMLButtonElement>(null)

  // Move focus into the modal the moment it opens - the safest actionable
  // option (Retry if available, else Continue), never the destructive Cancel.
  // Restore focus to the opener on close.
  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null
    ;(canRetry ? retryRef.current : continueRef.current)?.focus()
    return () => {
      if (opener && document.contains(opener)) opener.focus()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  function onKeyDown(e: React.KeyboardEvent) {
    // Escape must NOT activate Cancel - a stray keypress can't be equivalent to
    // an irreversible scan cancel. It moves focus to Cancel so the operator must
    // deliberately confirm with Enter/Space.
    if (e.key === 'Escape') {
      e.preventDefault()
      cancelRef.current?.focus()
      return
    }
    if (e.key !== 'Tab' || !dialogRef.current) return
    const focusables = dialogRef.current.querySelectorAll<HTMLElement>(
      'button:not([disabled])',
    )
    if (focusables.length === 0) return
    const first = focusables[0]
    const last = focusables[focusables.length - 1]
    const activeEl = document.activeElement
    if (e.shiftKey && activeEl === first) {
      e.preventDefault()
      last.focus()
    } else if (!e.shiftKey && activeEl === last) {
      e.preventDefault()
      first.focus()
    }
  }

  async function decide(action: ScanDecisionAction) {
    if (busy) return
    setPending(action)
    try {
      await onDecide(action)
    } finally {
      // For retry/continue the parent keeps polling; clear the button state so
      // the modal isn't stuck mid-flight if the status hasn't flipped yet.
      setPending(null)
    }
  }

  const entries = Object.entries(moduleErrors)

  return (
    <div
      ref={dialogRef}
      onKeyDown={onKeyDown}
      className="fixed inset-0 z-40 flex items-center justify-center px-4"
      role="dialog"
      aria-modal="true"
      aria-label="Module failure decision"
    >
      <div className="absolute inset-0 bg-canvas/70 backdrop-blur-sm" />
      <div className="glass relative w-full max-w-[520px] overflow-hidden rounded-[4px] onus-fade-up">
        <div className="flex items-start gap-3 border-b border-line px-5 py-4">
          <span className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-high/12">
            <AlertTriangle className="h-4 w-4 text-high" strokeWidth={1.8} />
          </span>
          <div>
            <h2 className="text-[15px] font-semibold text-ink">Some modules did not complete</h2>
            <p className="mt-0.5 text-[12.5px] text-ink-dim">
              Choose how to proceed. The rest of the scan is waiting on your decision.
            </p>
          </div>
        </div>

        <ul className="max-h-[240px] space-y-2 overflow-y-auto px-5 py-4">
          {entries.map(([id, err]) => (
            <li key={id} className="rounded-md border border-crit/25 bg-crit/[0.05] px-3 py-2.5">
              <p className="text-[12.5px] font-medium text-ink">{labelFor(id)}</p>
              <p className="mt-1 font-mono text-[11px] leading-relaxed text-crit/90">{err || 'Module failed.'}</p>
            </li>
          ))}
        </ul>

        <div className="flex flex-col gap-2 border-t border-line px-5 py-4">
          <button
            ref={retryRef}
            type="button"
            disabled={!canRetry || busy}
            onClick={() => decide('retry')}
            title={!canRetry ? 'Every failed module has already used its one retry.' : undefined}
            className={cn(
              'flex items-center justify-center gap-2 rounded-md px-4 py-2.5 text-[13px] font-semibold transition-colors',
              canRetry && !busy
                ? 'bg-accent text-white hover:bg-accent/90'
                : 'cursor-not-allowed bg-raised-2 text-ink-faint',
            )}
          >
            {pending === 'retry' ? <Spinner className="h-4 w-4" /> : <RotateCcw className="h-4 w-4" strokeWidth={1.8} />}
            {pending === 'retry' ? 'Retrying…' : 'Retry Failed Modules'}
          </button>

          <div className="grid grid-cols-2 gap-2">
            <button
              ref={continueRef}
              type="button"
              disabled={busy}
              onClick={() => decide('continue')}
              className="flex items-center justify-center gap-2 rounded-md border border-line-strong px-4 py-2.5 text-[13px] font-medium text-ink transition-colors hover:bg-white/[0.03] disabled:cursor-not-allowed disabled:opacity-50"
            >
              {pending === 'continue' ? <Spinner className="h-4 w-4" /> : <Play className="h-4 w-4" strokeWidth={1.8} />}
              {pending === 'continue' ? 'Continuing…' : 'Continue Without Them'}
            </button>
            <button
              ref={cancelRef}
              type="button"
              disabled={busy}
              onClick={() => decide('cancel')}
              className="flex items-center justify-center gap-2 rounded-md border border-crit/40 px-4 py-2.5 text-[13px] font-medium text-crit transition-colors hover:bg-crit/[0.08] disabled:cursor-not-allowed disabled:opacity-50"
            >
              {pending === 'cancel' ? <Spinner className="h-4 w-4" /> : <Ban className="h-4 w-4" strokeWidth={1.8} />}
              {pending === 'cancel' ? 'Cancelling…' : 'Cancel Scan'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
