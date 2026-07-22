import type { Metadata, Viewport } from 'next'
import { Instrument_Sans, Instrument_Serif, JetBrains_Mono } from 'next/font/google'
import { GoogleAnalytics } from '@next/third-parties/google'
import { AuthGate } from '@/components/auth-gate'
import './globals.css'

// Optional, privacy-first GA4. Loads ONLY when NEXT_PUBLIC_GA_ID is set and this
// is a production build — self-hosting without the var is completely unaffected.
// Page views are automatic (@next/third-parties + GA4 Enhanced Measurement);
// custom events go through lib/analytics.ts's trackEvent().
const GA_ID = process.env.NEXT_PUBLIC_GA_ID
const analyticsEnabled = !!GA_ID && process.env.NODE_ENV === 'production'

// DIRECTION C typographic thesis - printed field manual:
//   Instrument Serif → large high-contrast DISPLAY headings, upright + italic
//                      (the italic cut carries the periwinkle accent word)
//   Instrument Sans  → body PROSE, labels, buttons
//   JetBrains Mono   → dense crisp DATA (scores, IPs, timestamps, evidence)
const instrumentSerif = Instrument_Serif({
  variable: '--font-instrument-serif',
  subsets: ['latin'],
  weight: ['400'],
  style: ['normal', 'italic'],
})
const instrumentSans = Instrument_Sans({
  variable: '--font-instrument-sans',
  subsets: ['latin'],
  weight: ['400', '500', '600', '700'],
})
const jbMono = JetBrains_Mono({
  variable: '--font-jbmono',
  subsets: ['latin'],
  weight: ['400', '500', '600', '700'],
})

export const metadata: Metadata = {
  title: 'ONUS - Find security risks before attackers do.',
  description:
    'ONUS runs deterministic, verifiable vulnerability assessments. Evidence decides; AI only explains.',
}

export const viewport: Viewport = {
  colorScheme: 'light',
  themeColor: '#f6f3ec',
  width: 'device-width',
  initialScale: 1,
  // Extend under the notch / Dynamic Island so full-bleed canvases fill the
  // screen; fixed UI uses env(safe-area-inset-*) to stay clear of it.
  viewportFit: 'cover',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="en"
      className={`${instrumentSerif.variable} ${instrumentSans.variable} ${jbMono.variable}`}
    >
      <body className="min-h-screen font-sans antialiased">
        <AuthGate>{children}</AuthGate>
      </body>
      {analyticsEnabled && GA_ID && <GoogleAnalytics gaId={GA_ID} />}
    </html>
  )
}
