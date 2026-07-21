/**
 * Anonymous product analytics (Google Analytics 4).
 *
 * GA is OPTIONAL and privacy-first. The gtag script loads only when
 * NEXT_PUBLIC_GA_ID is set AND this is a production build (wired in
 * app/layout.tsx). Page views are handled automatically by
 * @next/third-parties + GA4 Enhanced Measurement — this module only adds
 * typed custom events.
 *
 * `trackEvent` is a safe no-op when analytics is disabled, so call sites never
 * need their own guard.
 *
 * PRIVACY — hard rule: pass ONLY anonymous, low-cardinality usage data. NEVER
 * send scanned domains, scan results, vulnerabilities, report contents, the
 * authorization-checkbox state, API keys, job IDs, or any personal data as
 * event parameters. If in doubt, send the event with no params.
 */
import { sendGAEvent } from '@next/third-parties/google'

/** GA4 Measurement ID (e.g. "G-XXXXXXXXXX"); undefined disables analytics. */
export const GA_ID = process.env.NEXT_PUBLIC_GA_ID

/** GA is active only in a production build that has a Measurement ID set. */
export const analyticsEnabled = !!GA_ID && process.env.NODE_ENV === 'production'

/**
 * The closed set of product events ONUS tracks. Add new names here so every
 * call site stays type-checked and the taxonomy lives in exactly one place.
 */
export type AnalyticsEvent =
  | 'scan_started'
  | 'scan_completed'
  | 'report_generated'
  | 'report_downloaded'
  | 'github_repository_clicked'
  | 'documentation_clicked'
  | 'docker_install_clicked'
  | 'quick_scan_selected'
  | 'full_scan_selected'
  | 'practice_target_selected'

/**
 * Non-sensitive event parameters only — keep values low-cardinality (enums,
 * counts, booleans). Never identifiers, domains, or free-form user input.
 */
export type AnalyticsParams = Record<string, string | number | boolean>

/**
 * Send a product-usage event to GA4. Safe no-op when analytics is disabled.
 *
 * @example trackEvent('scan_started', { scan_mode: 'full' })
 */
export function trackEvent(event: AnalyticsEvent, params?: AnalyticsParams): void {
  if (!analyticsEnabled) return
  if (typeof window === 'undefined') return
  sendGAEvent('event', event, params ?? {})
}
