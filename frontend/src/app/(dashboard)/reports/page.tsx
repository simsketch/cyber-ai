import { Metadata } from 'next'
import { DashboardHeader } from '@/components/dashboard/header'
import { DashboardShell } from '@/components/dashboard/shell'
import { ReportsTable } from '@/components/reports/reports-table'

export const metadata: Metadata = {
  title: 'Reports',
  description: 'View and manage security reports',
}

export default function ReportsPage() {
  return (
    <DashboardShell>
      <DashboardHeader
        heading="Reports"
        text="View and manage security assessment reports."
      />
      <ReportsTable />
    </DashboardShell>
  )
} 