import { Metadata } from 'next'
import { DashboardHeader } from '@/components/dashboard/header'
import { DashboardShell } from '@/components/dashboard/shell'

export const metadata: Metadata = {
  title: 'Controls - Cyber AI',
  description: 'View and manage security controls and policies',
}

export default function ControlsPage() {
  return (
    <DashboardShell>
      <DashboardHeader
        heading="Security Controls"
        text="View and manage security controls and policies"
      />
      <div className="grid gap-4">
        {/* TODO: Add security controls components */}
      </div>
    </DashboardShell>
  )
} 