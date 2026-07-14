import type { Metadata, Viewport } from 'next'
import { Inter, JetBrains_Mono, Orbitron } from 'next/font/google'
import { AppShell } from '@/components/app-shell'
import './globals.css'

// DIRECTION B typographic thesis - dramatic duality, command-console register:
//   Orbitron       → extended geometric all-caps SIGNAGE (headers, major labels)
//   JetBrains Mono → dense crisp DATA (scores, IPs, timestamps, evidence)
//   Inter          → readable PROSE (AI narrative, descriptions)
const orbitron = Orbitron({
  variable: '--font-orbitron',
  subsets: ['latin'],
  weight: ['400', '500', '600', '700', '800'],
})
const jbMono = JetBrains_Mono({
  variable: '--font-jbmono',
  subsets: ['latin'],
  weight: ['400', '500', '600', '700'],
})
const inter = Inter({
  variable: '--font-inter',
  subsets: ['latin'],
  weight: ['400', '500', '600'],
})

export const metadata: Metadata = {
  title: 'ONUS // COMMAND CENTER',
  description:
    'ONUS runs deterministic, verifiable vulnerability assessments. Evidence decides; AI only explains.',
}

export const viewport: Viewport = {
  colorScheme: 'dark',
  themeColor: '#030304',
  width: 'device-width',
  initialScale: 1,
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${orbitron.variable} ${jbMono.variable} ${inter.variable}`}>
      <body className="min-h-screen font-sans antialiased">
        <AppShell>{children}</AppShell>
      </body>
    </html>
  )
}
