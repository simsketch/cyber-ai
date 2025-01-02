'use client'

import { useEffect, useState } from 'react'
import { DashboardHeader } from '@/components/dashboard/header'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Skeleton } from '@/components/ui/skeleton'
import { formatDistanceToNow } from 'date-fns'
import { useToast } from '@/components/ui/use-toast'

interface CVE {
  id: string
  summary: string
  cvss: number
  references: string[]
  Published: string
  Modified: string
}

export default function CVEPage() {
  const [cves, setCves] = useState<CVE[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const { toast } = useToast()

  useEffect(() => {
    const fetchCVEs = async () => {
      try {
        setLoading(true)
        setError(null)
        const response = await fetch('http://localhost:8000/api/v1/cves')
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`)
        }
        const data = await response.json()
        if (!data.cves || !Array.isArray(data.cves)) {
          throw new Error('Invalid data format received')
        }
        setCves(data.cves)
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to fetch CVEs'
        setError(message)
        toast({
          variant: "destructive",
          title: "Error",
          description: message
        })
      } finally {
        setLoading(false)
      }
    }

    fetchCVEs()
  }, [toast])

  const getSeverityColor = (cvss: number) => {
    if (cvss >= 9.0) return 'bg-destructive text-destructive-foreground'
    if (cvss >= 7.0) return 'bg-orange-500 text-white'
    if (cvss >= 4.0) return 'bg-yellow-500 text-black'
    return 'bg-green-500 text-white'
  }

  const getSeverityLabel = (cvss: number) => {
    if (cvss >= 9.0) return 'Critical'
    if (cvss >= 7.0) return 'High'
    if (cvss >= 4.0) return 'Medium'
    return 'Low'
  }

  const formatPublishedDate = (dateStr: string | undefined) => {
    if (!dateStr) return "No date available";
    try {
      return formatDistanceToNow(new Date(dateStr), { addSuffix: true });
    } catch (error) {
      console.error("Error formatting date:", dateStr, error);
      return "Unknown date";
    }
  }

  return (
    <div className="flex flex-col gap-8">
      <DashboardHeader
        heading="CVE Database"
        text="Latest Common Vulnerabilities and Exposures"
      />

      <div className="grid gap-4">
        <Card>
          <CardHeader>
            <CardTitle>Latest CVEs</CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[800px] pr-4">
              {loading ? (
                <div className="space-y-4">
                  {Array.from({ length: 5 }).map((_, i) => (
                    <div key={i} className="flex flex-col gap-2">
                      <Skeleton className="h-6 w-1/3" />
                      <Skeleton className="h-20 w-full" />
                    </div>
                  ))}
                </div>
              ) : error ? (
                <div className="flex items-center justify-center h-32 text-muted-foreground">
                  {error}
                </div>
              ) : cves.length === 0 ? (
                <div className="flex items-center justify-center h-32 text-muted-foreground">
                  No CVEs found
                </div>
              ) : (
                <div className="space-y-8">
                  {cves.map((cve) => (
                    <Card key={cve.id} className="p-4">
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <h3 className="text-lg font-semibold">{cve.id}</h3>
                          <Badge className={getSeverityColor(cve.cvss)}>
                            {getSeverityLabel(cve.cvss)} ({cve.cvss})
                          </Badge>
                        </div>
                        <div className="text-sm text-muted-foreground">
                          {formatPublishedDate(cve.Published)}
                        </div>
                      </div>
                      <p className="text-sm text-muted-foreground mb-4">{cve.summary}</p>
                      {cve.references && cve.references.length > 0 && (
                        <div>
                          <h4 className="text-sm font-semibold mb-2">References:</h4>
                          <ul className="text-sm space-y-1">
                            {cve.references.slice(0, 3).map((ref, index) => (
                              <li key={index}>
                                <a
                                  href={ref}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-blue-500 hover:underline break-all"
                                >
                                  {ref}
                                </a>
                              </li>
                            ))}
                            {cve.references.length > 3 && (
                              <li className="text-muted-foreground">
                                +{cve.references.length - 3} more references
                              </li>
                            )}
                          </ul>
                        </div>
                      )}
                      <div className="flex gap-4 mt-4 text-xs text-muted-foreground">
                        <div>Published: {new Date(cve.Published).toLocaleDateString()}</div>
                        <div>Modified: {new Date(cve.Modified).toLocaleDateString()}</div>
                      </div>
                    </Card>
                  ))}
                </div>
              )}
            </ScrollArea>
          </CardContent>
        </Card>
      </div>
    </div>
  )
} 