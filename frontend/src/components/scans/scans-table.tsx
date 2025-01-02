'use client'

import { useEffect } from 'react'
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query'
import { useUser } from '@clerk/nextjs'
import { getScans, cancelScan } from '@/lib/api/scans'
import { Scan } from '@/types/scans'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { format, parseISO } from 'date-fns'
import { ExternalLink, XCircle } from 'lucide-react'
import { useRouter } from 'next/navigation'
import { useToast } from '@/components/ui/use-toast'
import { ToastAction } from '@/components/ui/toast'
import { GlitchLogo } from '@/components/ui/glitch-logo'

function formatLocalDateTime(dateStr: string | null) {
  if (!dateStr) return 'N/A'
  try {
    const date = parseISO(dateStr)
    return format(date, 'PPpp')
  } catch (error) {
    console.error('Error formatting date:', error)
    return 'Invalid date'
  }
}

function formatDuration(startDate: string | null, endDate: string | null | undefined): string {
  if (!startDate) return 'N/A'
  try {
    const start = parseISO(startDate)
    const end = endDate ? parseISO(endDate) : new Date()
    return `${Math.round((end.getTime() - start.getTime()) / 1000)}s`
  } catch (error) {
    console.error('Error calculating duration:', error)
    return 'N/A'
  }
}

export function ScansTable() {
  const router = useRouter()
  const queryClient = useQueryClient()
  const { user, isLoaded: isUserLoaded } = useUser()
  const { toast } = useToast()
  
  const { data: scans, isLoading: isScansLoading, error } = useQuery({
    queryKey: ['scans', user?.id],
    queryFn: async () => {
      if (!user?.id) {
        console.error('No user ID available')
        throw new Error('No user ID')
      }
      console.log('Starting scan fetch for user:', user.id)
      try {
        const result = await getScans(user.id)
        console.log('Scan fetch result:', result)
        return result
      } catch (e) {
        console.error('Error in queryFn:', e)
        throw e
      }
    },
    enabled: !!user?.id && isUserLoaded,
    retry: 1
  })

  // Add cancel scan mutation
  const cancelMutation = useMutation({
    mutationFn: async (scanId: string) => {
      if (!user?.id) throw new Error('Not authenticated')
      return cancelScan(scanId, user.id)
    },
    onSuccess: () => {
      toast({
        title: 'Scan cancelled',
        description: 'The scan has been cancelled successfully.',
      })
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
    onError: (error) => {
      toast({
        title: 'Failed to cancel scan',
        description: error instanceof Error ? error.message : 'An error occurred',
        variant: 'destructive',
      })
    },
  })

  // Show toast for completed scans
  useEffect(() => {
    if (!scans) return

    const lastScan = scans[0]
    if (!lastScan) return

    const lastScanKey = `last-scan-${lastScan.id}`
    const lastStatus = sessionStorage.getItem(lastScanKey)

    if (lastStatus !== lastScan.status) {
      sessionStorage.setItem(lastScanKey, lastScan.status)

      if (lastScan.status === 'completed') {
        toast({
          title: `${lastScan.scan_type === 'comprehensive' ? 'Comprehensive' : 'Quick'} Scan Completed`,
          description: `Scan of ${lastScan.target} completed with ${lastScan.total_vulnerabilities} findings.`,
          variant: lastScan.total_vulnerabilities > 0 ? "warning" : "success",
          duration: 5000,
          action: lastScan.total_vulnerabilities > 0 ? (
            <ToastAction altText="View scan details" onClick={() => router.push(`/scans/${lastScan.id}`)}>
              View Details
            </ToastAction>
          ) : undefined
        })
      } else if (lastScan.status === 'failed') {
        toast({
          title: "Scan Failed",
          description: lastScan.error || "An error occurred during the scan.",
          variant: "destructive",
          duration: 5000
        })
      }
    }
  }, [scans, toast, router])

  if (!isUserLoaded) {
    return null
  }

  if (isScansLoading) {
    return (
      <div className="flex h-[200px] items-center justify-center rounded-md border">
        <GlitchLogo />
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex h-[200px] items-center justify-center rounded-md border">
        <p className="text-sm text-muted-foreground">Failed to load scans. Please try again.</p>
      </div>
    )
  }

  if (!scans?.length) {
    return (
      <div className="flex h-[200px] items-center justify-center rounded-md border">
        <p className="text-sm text-muted-foreground">No scans found.</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Recent Scans</h2>
      </div>
      
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Target</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Progress</TableHead>
              <TableHead>Message</TableHead>
              <TableHead>Vulnerabilities</TableHead>
              <TableHead>Started</TableHead>
              <TableHead>Duration</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {scans.map((scan) => (
              <TableRow key={scan.id}>
                <TableCell className="font-medium">{scan.target}</TableCell>
                <TableCell>
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
                </TableCell>
                <TableCell>
                  {scan.status === 'in-progress' && (
                    <div className="w-[100px]">
                      <Progress value={scan.progress || 0} className="h-2" />
                    </div>
                  )}
                </TableCell>
                <TableCell>
                  <span className="text-sm text-muted-foreground">
                    {scan.message || '-'}
                  </span>
                </TableCell>
                <TableCell>{scan.total_vulnerabilities}</TableCell>
                <TableCell>
                  {formatLocalDateTime(scan.started_at)}
                </TableCell>
                <TableCell>
                  {formatDuration(scan.started_at, scan.completed_at)}
                </TableCell>
                <TableCell className="text-right">
                  <div className="flex justify-end gap-2">
                    {scan.status === 'in-progress' && (
                      <Button
                        variant="destructive"
                        size="sm"
                        onClick={() => cancelMutation.mutate(scan.id)}
                        disabled={cancelMutation.isPending}
                        className="inline-flex items-center gap-2"
                      >
                        <XCircle className="h-4 w-4" />
                        Cancel
                      </Button>
                    )}
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => router.push(`/scans/${scan.id}`)}
                      className="inline-flex items-center gap-2"
                    >
                      <ExternalLink className="h-4 w-4" />
                      View Details
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  )
} 