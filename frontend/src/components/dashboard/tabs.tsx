'use client'

import { Card, CardContent } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'

export function DashboardTabs() {
  return (
    <Tabs defaultValue="overview" className="space-y-4">
      <TabsList>
        <TabsTrigger value="overview">Overview</TabsTrigger>
        <TabsTrigger value="analytics">Analytics</TabsTrigger>
        <TabsTrigger value="reports">Reports</TabsTrigger>
      </TabsList>
      <TabsContent value="overview">
        <Card>
          <CardContent className="space-y-2 pt-6">
            <div className="space-y-1">
              <h3 className="font-medium">Security Overview</h3>
              <p className="text-sm text-muted-foreground">
                Your security posture is currently at moderate risk. There are 3
                critical vulnerabilities that need attention.
              </p>
            </div>
          </CardContent>
        </Card>
      </TabsContent>
      <TabsContent value="analytics">
        <Card>
          <CardContent className="space-y-2 pt-6">
            <div className="space-y-1">
              <h3 className="font-medium">Security Analytics</h3>
              <p className="text-sm text-muted-foreground">
                View detailed analytics about your security scans, vulnerabilities,
                and remediation progress.
              </p>
            </div>
          </CardContent>
        </Card>
      </TabsContent>
      <TabsContent value="reports">
        <Card>
          <CardContent className="space-y-2 pt-6">
            <div className="space-y-1">
              <h3 className="font-medium">Security Reports</h3>
              <p className="text-sm text-muted-foreground">
                Access and download detailed security reports and compliance
                documentation.
              </p>
            </div>
          </CardContent>
        </Card>
      </TabsContent>
    </Tabs>
  )
} 