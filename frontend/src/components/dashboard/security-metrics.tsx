'use client'

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

type Metrics = {
  totalScans: number
  activeScans: number
  totalVulnerabilities: number
  criticalVulnerabilities: number
}

const mockMetrics: Metrics = {
  totalScans: 24,
  activeScans: 2,
  totalVulnerabilities: 48,
  criticalVulnerabilities: 3,
}

export function SecurityMetrics() {
  return (
    <>
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold" suppressHydrationWarning>{mockMetrics.totalScans}</div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Active Scans</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold" suppressHydrationWarning>{mockMetrics.activeScans}</div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Total Vulnerabilities</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold" suppressHydrationWarning>{mockMetrics.totalVulnerabilities}</div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Critical Vulnerabilities</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-destructive" suppressHydrationWarning>
            {mockMetrics.criticalVulnerabilities}
          </div>
        </CardContent>
      </Card>
    </>
  )
} 