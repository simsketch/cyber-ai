'use client'

import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

type NetworkStats = {
  totalAssets: number
  servers: number
  clients: number
  networkDevices: number
  vulnerableAssets: number
}

const mockStats: NetworkStats = {
  totalAssets: 24,
  servers: 8,
  clients: 12,
  networkDevices: 4,
  vulnerableAssets: 3,
}

export function NetworkStats() {
  const [stats] = useState<NetworkStats>(mockStats)

  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Total Assets</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{stats.totalAssets}</div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Servers</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{stats.servers}</div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Clients</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{stats.clients}</div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Network Devices</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{stats.networkDevices}</div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Vulnerable Assets</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-destructive">
            {stats.vulnerableAssets}
          </div>
        </CardContent>
      </Card>
    </div>
  )
} 