'use client'

import { useState } from 'react'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

type Vulnerability = {
  id: string
  title: string
  severity: Severity
  status: 'open' | 'fixed' | 'false-positive'
  target: string
  discoveredAt: Date
}

const mockVulnerabilities: Vulnerability[] = [
  {
    id: '1',
    title: 'SQL Injection in Login Form',
    severity: 'critical',
    status: 'open',
    target: 'example.com/login',
    discoveredAt: new Date('2023-12-29T10:00:00'),
  },
  {
    id: '2',
    title: 'Cross-Site Scripting (XSS)',
    severity: 'high',
    status: 'fixed',
    target: 'example.com/comments',
    discoveredAt: new Date('2023-12-29T11:00:00'),
  },
]

const severityColors: Record<
  Severity,
  'destructive' | 'default' | 'secondary' | 'outline'
> = {
  critical: 'destructive',
  high: 'destructive',
  medium: 'default',
  low: 'secondary',
  info: 'secondary',
}

export function VulnerabilitiesTable() {
  const [vulnerabilities] = useState<Vulnerability[]>(mockVulnerabilities)

  return (
    <div className="rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Title</TableHead>
            <TableHead>Severity</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Target</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {vulnerabilities.map((vuln) => (
            <TableRow key={vuln.id}>
              <TableCell className="font-medium">{vuln.title}</TableCell>
              <TableCell>
                <Badge variant={severityColors[vuln.severity]}>
                  {vuln.severity}
                </Badge>
              </TableCell>
              <TableCell>
                <Badge
                  variant={
                    vuln.status === 'fixed'
                      ? 'secondary'
                      : vuln.status === 'false-positive'
                      ? 'default'
                      : 'destructive'
                  }
                >
                  {vuln.status}
                </Badge>
              </TableCell>
              <TableCell>{vuln.target}</TableCell>
              <TableCell className="text-right">
                <Button variant="ghost" size="sm">
                  View Details
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
} 