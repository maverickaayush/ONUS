#!/usr/bin/env node
/**
 * Public-build trim. Removes excluded routes from app/ so they are absent from
 * the Next bundle, not merely unreachable. Kept: /scan/new, /scans,
 * /scan/[id]/status and /scan/[id]/report. Removed: landing (/), /sign-in,
 * /sign-up, /admin. Root (/) is repointed to serve the scan form.
 */
import { existsSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const APP = new URL('../app/', import.meta.url).pathname
const COMP = new URL('../components/', import.meta.url).pathname

for (const r of ['sign-in', 'sign-up', 'admin']) {
  const p = join(APP, r)
  if (existsSync(p)) { rmSync(p, { recursive: true, force: true }); console.log('removed app/' + r) }
}
writeFileSync(join(APP, 'page.tsx'),
  "import { NewScan } from '@/components/new-scan'\n\n" +
  "// Public/self-hosted root: the scan form is the home page. No marketing\n" +
  "// landing, no sign-in wall - a single-operator local instance opens straight\n" +
  "// to scanning.\nexport default function Page() {\n  return <NewScan />\n}\n")
console.log('repointed app/page.tsx -> NewScan')
const landing = join(COMP, 'landing.tsx')
if (existsSync(landing)) { rmSync(landing); console.log('removed components/landing.tsx') }
console.log('public trim complete')
