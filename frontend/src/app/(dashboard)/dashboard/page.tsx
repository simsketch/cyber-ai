import { Metadata } from 'next'
import { DashboardHeader } from '@/components/dashboard/header'
import { DashboardShell } from '@/components/dashboard/shell'
import { DashboardTabs } from '@/components/dashboard/tabs'
import { RiskScoreChart } from '@/components/dashboard/risk-score-chart'
import { VulnerabilityDistribution } from '@/components/dashboard/vulnerability-distribution'
import { SecurityMetrics } from '@/components/dashboard/security-metrics'
import { RecentScans } from '@/components/dashboard/recent-scans'
import { StartScan } from '@/components/dashboard/start-scan'

export const metadata: Metadata = {
  title: 'Dashboard - Cyber AI',
  description: 'Security overview and analytics dashboard',
}

export default function DashboardPage() {
  return (
    <DashboardShell>
      <DashboardHeader
        heading="Dashboard"
        text="Security overview and analytics dashboard"
      />
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <SecurityMetrics />
      </div>
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
        <div className="col-span-4">
          <div className="grid gap-4">
            <StartScan />
            <DashboardTabs />
            <RiskScoreChart />
          </div>
        </div>
        <div className="col-span-3">
          <div className="grid gap-4">
            <VulnerabilityDistribution />
            <RecentScans />
          </div>
        </div>
      </div>
    </DashboardShell>
  )
} 