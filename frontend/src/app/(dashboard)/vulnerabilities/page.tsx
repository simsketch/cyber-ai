import { DashboardHeader } from '@/components/dashboard/header'
import { DashboardShell } from '@/components/dashboard/shell'
import { VulnerabilitiesTable } from '@/components/vulnerabilities/vulnerabilities-table'
import { VulnerabilityDistribution } from '@/components/dashboard/vulnerability-distribution'

export const metadata = {
  title: 'Vulnerabilities - Cyber AI',
  description: 'View and manage discovered vulnerabilities',
}

export default function VulnerabilitiesPage() {
  return (
    <DashboardShell>
      <DashboardHeader
        heading="Vulnerabilities"
        text="View and manage discovered vulnerabilities"
      />
      <div className="grid gap-4">
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
          <div className="col-span-4">
            <VulnerabilitiesTable />
          </div>
          <div className="col-span-3">
            <VulnerabilityDistribution />
          </div>
        </div>
      </div>
    </DashboardShell>
  )
} 