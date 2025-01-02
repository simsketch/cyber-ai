import { DashboardHeader } from '@/components/dashboard/header'
import { DashboardShell } from '@/components/dashboard/shell'
import { ScansTable } from '@/components/scans/scans-table'
import { StartScan } from '@/components/dashboard/start-scan'

export const metadata = {
  title: 'Scans - Cyber AI',
  description: 'View and manage your security scans',
}

export default function ScansPage() {
  return (
    <DashboardShell>
      <DashboardHeader
        heading="Scans"
        text="View and manage your security scans"
      />
      <div className="grid gap-4">
        <StartScan />
        <ScansTable />
      </div>
    </DashboardShell>
  )
} 