import { Navbar } from "@/components/vapt/navbar"
import { ScanStatus } from "@/components/vapt/scan-status"

export default async function ScanStatusPage({
  params,
}: { params: Promise<{ id: string }> }) {
  const { id } = await params
  return (
    <>
      <Navbar />
      <ScanStatus jobId={id} domain="" />
    </>
  )
}
