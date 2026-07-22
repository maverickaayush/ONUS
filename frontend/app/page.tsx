import { NewScan } from '@/components/new-scan'

// Public/self-hosted root: the scan form is the home page. No marketing
// landing, no sign-in wall - a single-operator local instance opens straight
// to scanning.
export default function Page() {
  return <NewScan />
}
