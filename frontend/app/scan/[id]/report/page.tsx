import { Navbar } from "@/components/vapt/navbar"
import { ReportDashboard } from "@/components/vapt/report-dashboard"

export default async function ReportPage({
  params,
}: { params: Promise<{ id: string }> }) {
  const { id } = await params
  return (
    <>
      <Navbar />
      <ReportDashboard jobId={id} />
    </>
  )
}
