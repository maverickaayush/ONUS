import { ScanStatus } from '@/components/scan-status'

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  return <ScanStatus jobId={id} />
}
