import { Suspense } from 'react'
import { ScansList } from '@/components/scans-list'

export default function Page() {
  return (
    <Suspense fallback={null}>
      <ScansList />
    </Suspense>
  )
}
