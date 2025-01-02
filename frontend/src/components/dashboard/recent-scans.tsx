'use client'

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { formatDistanceToNow } from 'date-fns'

type Scan = {
  id: string
  target: string
  status: 'pending' | 'in-progress' | 'completed' | 'failed'
  startedAt: Date
  vulnerabilities: number
}

const mockScans: Scan[] = [
  {
    id: '1',
    target: 'example.com',
    status: 'completed',
    startedAt: new Date('2023-12-29T10:00:00'),
    vulnerabilities: 3,
  },
  {
    id: '2',
    target: 'test.com',
    status: 'in-progress',
    startedAt: new Date('2023-12-29T11:30:00'),
    vulnerabilities: 0,
  },
]

export function RecentScans() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent Scans</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-8">
          {mockScans.map((scan) => (
            <div key={scan.id} className="flex items-center">
              <div className="ml-4 space-y-1">
                <p className="text-sm font-medium leading-none">{scan.target}</p>
                <p className="text-sm text-muted-foreground" suppressHydrationWarning>
                  {formatDistanceToNow(scan.startedAt, { addSuffix: true })}
                </p>
              </div>
              <div className="ml-auto flex items-center gap-2">
                <Badge
                  variant={
                    scan.status === 'completed'
                      ? 'secondary'
                      : scan.status === 'in-progress'
                      ? 'default'
                      : 'destructive'
                  }
                >
                  {scan.status}
                </Badge>
                <span className="text-sm text-muted-foreground" suppressHydrationWarning>
                  {scan.vulnerabilities} vulnerabilities
                </span>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
} 