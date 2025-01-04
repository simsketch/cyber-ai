'use client'

import { useQuery } from '@tanstack/react-query'
import { useUser } from '@auth0/nextjs-auth0/client'
import { getReports } from '@/lib/api/reports'
import { Report } from '@/types/reports'
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
import { format } from 'date-fns'
import { Loader2, ExternalLink } from 'lucide-react'
import { useRouter } from 'next/navigation'
import { GlitchLogo } from '../ui/glitch-logo'

export function ReportsTable() {
  const router = useRouter()
  const { user, isLoading: isUserLoading } = useUser()
  
  const { data: reports, isLoading: isReportsLoading, error } = useQuery({
    queryKey: ['reports', user?.sub],
    queryFn: async () => {
      if (!user?.sub) {
        console.error('No user ID available')
        throw new Error('No user ID')
      }
      console.log('Starting reports fetch for user:', user.sub)
      try {
        const result = await getReports(user.sub)
        console.log('Reports fetch result:', result)
        return result
      } catch (e) {
        console.error('Error in queryFn:', e)
        throw e
      }
    },
    enabled: !!user?.sub && !isUserLoading
  })

  if (isUserLoading) {
    return null
  }

  if (isReportsLoading || error) {
    return (
      <div className="flex flex-col h-[200px] items-center justify-center gap-4 rounded-md border">
        {isReportsLoading && <GlitchLogo loading={true} />}
        {error && <p className="text-sm text-muted-foreground">Failed to load reports. Please try again.</p>}
      </div>
    )
  }

  if (!reports?.length) {
    return (
      <div className="flex h-[200px] items-center justify-center rounded-md border">
        <p className="text-sm text-muted-foreground">No reports found.</p>
      </div>
    )
  }

  return (
    <div className="rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Target</TableHead>
            <TableHead>Generated</TableHead>
            <TableHead>Vulnerabilities</TableHead>
            <TableHead>High</TableHead>
            <TableHead>Medium</TableHead>
            <TableHead>Low</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {reports.map((report) => (
            <TableRow key={report._id}>
              <TableCell className="font-medium">{report.data.target}</TableCell>
              <TableCell>
                {report.generated_at ? format(new Date(report.generated_at), 'PPp') : 'N/A'}
              </TableCell>
              <TableCell>{report.data.total_vulnerabilities}</TableCell>
              <TableCell>
                <Badge variant="destructive">{report.data.findings_summary.high}</Badge>
              </TableCell>
              <TableCell>
                <Badge variant="default">{report.data.findings_summary.medium}</Badge>
              </TableCell>
              <TableCell>
                <Badge variant="secondary">{report.data.findings_summary.low}</Badge>
              </TableCell>
              <TableCell className="text-right">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => router.push(`/reports/${report._id}`)}
                  className="inline-flex items-center gap-2"
                >
                  <ExternalLink className="h-4 w-4" />
                  View Report
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
} 