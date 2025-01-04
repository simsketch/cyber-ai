'use client'

import { useQuery } from '@tanstack/react-query'
import { useUser } from '@auth0/nextjs-auth0/client'
import { getScan } from '@/lib/api/scans'
import { Loader2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { format } from 'date-fns'
import { Button } from '@/components/ui/button'
import { useRouter } from 'next/navigation'
import { ArrowLeft } from 'lucide-react'
import { GlitchLogo } from '@/components/ui/glitch-logo'

export default function ScanDetailsPage({ params }: { params: { id: string } }) {
  const router = useRouter()
  const { user, isLoading: isUserLoading } = useUser()
  
  const { data: scan, isLoading, error } = useQuery({
    queryKey: ['scan', params.id],
    queryFn: async () => {
      if (!user?.sub) throw new Error('Not authenticated')
      return getScan(params.id, user.sub)
    },
    enabled: !!user?.sub && !isUserLoading
  })

  if (isUserLoading) {
    return null
  }

  if (isLoading) {
    return (
      <GlitchLogo />  
    )
  }

  if (error || !scan) {
    return (
      <div className="flex h-[400px] items-center justify-center">
        <p className="text-sm text-muted-foreground">Failed to load scan details. Please try again later.</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <Button
          variant="ghost"
          onClick={() => router.back()}
          className="inline-flex items-center gap-2"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Scans
        </Button>
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
      </div>

      <div className="rounded-lg border bg-card p-6">
        <h2 className="text-2xl font-bold mb-4">Scan Details</h2>
        
        <div className="grid gap-4">
          <div className="grid grid-cols-2 gap-2">
            <span className="text-muted-foreground">Target:</span>
            <span>{scan.target}</span>
          </div>
          
          <div className="grid grid-cols-2 gap-2">
            <span className="text-muted-foreground">Started:</span>
            <span>{scan.started_at ? format(new Date(scan.started_at), 'PPp') : 'N/A'}</span>
          </div>

          <div className="grid grid-cols-2 gap-2">
            <span className="text-muted-foreground">Duration:</span>
            <span>
              {scan.completed_at && scan.started_at
                ? `${Math.round(
                    (new Date(scan.completed_at).getTime() -
                      new Date(scan.started_at).getTime()) /
                      1000
                  )}s`
                : 'N/A'}
            </span>
          </div>

          <div className="grid grid-cols-2 gap-2">
            <span className="text-muted-foreground">Total Vulnerabilities:</span>
            <span>{scan.total_vulnerabilities}</span>
          </div>
        </div>

        {scan.vulnerabilities && scan.vulnerabilities.length > 0 && (
          <div className="mt-8">
            <h3 className="text-xl font-semibold mb-4">Vulnerabilities</h3>
            <div className="space-y-4">
              {scan.vulnerabilities.map((vuln, index) => (
                <div key={index} className="rounded-md border p-4">
                  <h4 className="font-medium mb-2">{vuln.title}</h4>
                  <p className="text-sm text-muted-foreground mb-2">{vuln.description}</p>
                  <Badge variant={vuln.severity === 'high' ? 'destructive' : 'secondary'}>
                    {vuln.severity}
                  </Badge>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
} 