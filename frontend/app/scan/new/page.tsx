import { NewScan } from '@/components/new-scan'

// The scan console. Static segment, so it takes precedence over /scan/[id].
// Still guarded by AuthGate — only '/' was opened up for the landing.
export default function Page() {
  return <NewScan />
}
