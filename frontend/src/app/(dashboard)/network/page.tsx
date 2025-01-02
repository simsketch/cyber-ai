import { Metadata } from 'next'
import { DashboardHeader } from '@/components/dashboard/header'
import { DashboardShell } from '@/components/dashboard/shell'

export const metadata: Metadata = {
  title: 'Network - Cyber AI',
  description: 'Network monitoring and analysis',
}

export default function NetworkPage() {
  return (
    <DashboardShell>
      <DashboardHeader
        heading="Network"
        text="Network monitoring and analysis"
      />
      <div className="grid gap-4">
        <div className="rounded-lg border p-8">
          <p className="text-muted-foreground">Network monitoring features coming soon.</p>
        </div>
      </div>
    </DashboardShell>
  )
} 