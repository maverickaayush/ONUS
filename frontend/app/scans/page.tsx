import { Suspense } from "react"
import { Navbar } from "@/components/vapt/navbar"
import { ScansList } from "@/components/vapt/scans-list"

export default function ScansPage() {
  return (
    <>
      <Navbar />
      {/* ScansList reads view state via useSearchParams, which Next.js
          requires to be wrapped in Suspense during static rendering. */}
      <Suspense fallback={null}>
        <ScansList />
      </Suspense>
    </>
  )
}
