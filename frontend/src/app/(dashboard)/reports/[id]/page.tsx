'use client'

import { useQuery } from '@tanstack/react-query'
import { useUser } from '@auth0/nextjs-auth0/client'
import { getReport } from '@/lib/api/reports'
import { ArrowLeft, AlertTriangle, Shield, ShieldAlert } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useRouter } from 'next/navigation'
import { format, parseISO } from 'date-fns'
import ReactMarkdown from 'react-markdown'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion'
import { GlitchLogo } from '@/components/ui/glitch-logo'

const SEVERITY_COLORS = {
  high: '#ef4444',
  medium: '#f97316',
  low: '#22c55e'
}

const SEVERITY_ICONS = {
  high: ShieldAlert,
  medium: AlertTriangle,
  low: Shield
}

// Add a helper function to format dates
function formatLocalDateTime(dateStr: string) {
  try {
    const date = parseISO(dateStr)
    return format(date, 'PPpp')
  } catch (error) {
    console.error('Error formatting date:', error)
    return 'Invalid date'
  }
}

// Move the client component logic to a separate component
function ReportDetails({ id }: { id: string }) {
  const router = useRouter()
  const { user, isLoading: isUserLoading } = useUser()
  
  const { data: report, isLoading, error } = useQuery({
    queryKey: ['report', id],
    queryFn: async () => {
      if (!user?.sub) throw new Error('Not authenticated')
      return getReport(id, user.sub)
    },
    enabled: !!user?.sub && !isUserLoading
  })

  if (isUserLoading || isLoading) {
    return (
      <div className="flex h-[400px] items-center justify-center">
        <GlitchLogo />
      </div>
    )
  }

  if (error || !report) {
    return (
      <div className="flex h-[400px] items-center justify-center">
        <p className="text-sm text-muted-foreground">Failed to load report details. Please try again later.</p>
      </div>
    )
  }

  const chartData = [
    { name: 'High', value: report.data.findings_summary.high },
    { name: 'Medium', value: report.data.findings_summary.medium },
    { name: 'Low', value: report.data.findings_summary.low }
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <Button
          variant="ghost"
          onClick={() => router.back()}
          className="inline-flex items-center gap-2"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Reports
        </Button>
        <Badge variant="outline">{report.type}</Badge>
      </div>

      <div className="grid gap-6">
        {/* Header Card */}
        <Card>
          <CardHeader>
            <CardTitle>{report.title}</CardTitle>
            <p className="text-sm text-muted-foreground">{report.description}</p>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              <div>
                <p className="text-sm font-medium">Target</p>
                <p className="text-2xl font-bold">{report.data.target}</p>
              </div>
              <div>
                <p className="text-sm font-medium">Total Vulnerabilities</p>
                <p className="text-2xl font-bold">{report.data.total_vulnerabilities}</p>
              </div>
              <div>
                <p className="text-sm font-medium">Scan Duration</p>
                <p className="text-2xl font-bold">{report.scan_duration ? `${Math.round(report.scan_duration)}s` : 'N/A'}</p>
              </div>
              <div>
                <p className="text-sm font-medium">Generated</p>
                <p className="text-2xl font-bold">{formatLocalDateTime(report.generated_at)}</p>
              </div>
              <div>
                <p className="text-sm font-medium">Health Score</p>
                <div className="flex items-center gap-2">
                  <p className="text-2xl font-bold">{report.health_score || 'N/A'}</p>
                  {report.health_score && (
                    <Badge variant={
                      report.health_score >= 80 ? "success" :
                      report.health_score >= 60 ? "warning" :
                      "destructive"
                    }>
                      {report.health_rating}
                    </Badge>
                  )}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Action Items Card */}
        {report.data.vulnerabilities.length > 0 && (
          <Card className="border-destructive">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-destructive" />
                Priority Action Items
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {/* High Severity Vulnerabilities */}
                {report.data.vulnerabilities
                  .filter(vuln => vuln.severity === 'high')
                  .slice(0, 3)
                  .map((vuln, index) => (
                    <div key={index} className="flex items-start gap-2">
                      <ShieldAlert className="h-5 w-5 mt-0.5 text-destructive" />
                      <div>
                        <p className="font-medium">{vuln.title}</p>
                        <p className="text-sm text-muted-foreground">{vuln.description}</p>
                        {vuln.remediation && (
                          <p className="text-sm mt-1">
                            <span className="font-medium">Fix: </span>
                            {vuln.remediation}
                          </p>
                        )}
                      </div>
                    </div>
                  ))}

                {/* Exposed Services */}
                {report.data.port_results?.open_ports
                  ?.filter(port => [21, 23, 3389, 445].includes(port.port))
                  .map((port, index) => (
                    <div key={`port-${index}`} className="flex items-start gap-2">
                      <AlertTriangle className="h-5 w-5 mt-0.5 text-destructive" />
                      <div>
                        <p className="font-medium">Exposed {port.service} Service on Port {port.port}</p>
                        <p className="text-sm text-muted-foreground">
                          Critical service exposed to potential attacks. Consider restricting access or disabling if not required.
                        </p>
                      </div>
                    </div>
                  ))}

                {/* View All Button */}
                <Button
                  variant="outline"
                  className="w-full mt-4"
                  onClick={() => document.getElementById('vulnerabilities')?.scrollIntoView({ behavior: 'smooth' })}
                >
                  View All Issues
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Charts Row */}
        <div className="grid md:grid-cols-2 gap-6">
          <Card>
            <CardHeader>
              <CardTitle>Findings by Severity</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="h-[300px]">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={chartData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={80}
                      paddingAngle={5}
                      dataKey="value"
                    >
                      <Cell fill={SEVERITY_COLORS.high} />
                      <Cell fill={SEVERITY_COLORS.medium} />
                      <Cell fill={SEVERITY_COLORS.low} />
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Severity Summary</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {Object.entries(report.data.findings_summary).map(([severity, count]) => {
                  const Icon = SEVERITY_ICONS[severity as keyof typeof SEVERITY_ICONS]
                  return (
                    <div key={severity} className="flex items-center gap-4">
                      <Icon className={`h-5 w-5 text-${severity}`} />
                      <div className="flex-1">
                        <p className="text-sm font-medium capitalize">{severity}</p>
                        <div className="h-2 rounded-full bg-secondary mt-1">
                          <div
                            className="h-2 rounded-full"
                            style={{
                              width: `${(count / report.data.total_vulnerabilities) * 100}%`,
                              backgroundColor: SEVERITY_COLORS[severity as keyof typeof SEVERITY_COLORS]
                            }}
                          />
                        </div>
                      </div>
                      <span className="text-sm font-medium">{count}</span>
                    </div>
                  )
                })}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* AI Analysis Summary */}
        {report.ai_summary && (
          <Card>
            <Accordion type="single" collapsible defaultValue="ai-analysis">
              <AccordionItem value="ai-analysis">
                <AccordionTrigger className="px-6">
                  <div className="flex items-center gap-2 text-lg font-semibold">
                    AI Analysis Summary
                    <Badge variant="secondary">AI Generated</Badge>
                  </div>
                </AccordionTrigger>
                <AccordionContent className="px-6 pb-6">
                  <div className="prose dark:prose-invert max-w-none">
                    <ReactMarkdown>{report.ai_summary}</ReactMarkdown>
                  </div>
                </AccordionContent>
              </AccordionItem>
            </Accordion>
          </Card>
        )}

        {/* Detailed Analysis */}
        {report.markdown_content && (
          <Card>
            <Accordion type="single" collapsible>
              <AccordionItem value="detailed-analysis">
                <AccordionTrigger className="px-6">
                  <div className="flex items-center gap-2 text-lg font-semibold">
                    Detailed Analysis
                  </div>
                </AccordionTrigger>
                <AccordionContent className="px-6 pb-6">
                  <div className="prose dark:prose-invert max-w-none">
                    <ReactMarkdown>{report.markdown_content}</ReactMarkdown>
                  </div>
                </AccordionContent>
              </AccordionItem>
            </Accordion>
          </Card>
        )}

        {/* Vulnerabilities List */}
        <Card>
          <Accordion type="single" collapsible defaultValue="vulnerabilities">
            <AccordionItem value="vulnerabilities">
              <AccordionTrigger className="px-6">
                <div className="flex items-center gap-2 text-lg font-semibold">
                  Vulnerabilities
                  {report.data.total_vulnerabilities > 0 && (
                    <Badge variant="secondary">{report.data.total_vulnerabilities}</Badge>
                  )}
                </div>
              </AccordionTrigger>
              <AccordionContent className="px-6 pb-6">
                <div className="space-y-6">
                  {/* Group vulnerabilities by severity */}
                  {['high', 'medium', 'low'].map((severity) => {
                    const vulnsOfSeverity = report.data.vulnerabilities.filter(v => v.severity === severity);
                    if (vulnsOfSeverity.length === 0) return null;
                    
                    return (
                      <div key={severity} className="space-y-4">
                        <h3 className="font-semibold flex items-center gap-2 text-lg">
                          {severity === 'high' && <ShieldAlert className="h-5 w-5 text-destructive" />}
                          {severity === 'medium' && <AlertTriangle className="h-5 w-5 text-orange-500" />}
                          {severity === 'low' && <Shield className="h-5 w-5 text-green-500" />}
                          {severity.charAt(0).toUpperCase() + severity.slice(1)} Severity Findings ({vulnsOfSeverity.length})
                        </h3>
                        {vulnsOfSeverity.map((vuln, index) => (
                          <Card key={index}>
                            <CardHeader>
                              <div className="flex items-center justify-between">
                                <CardTitle className="text-base">{vuln.title}</CardTitle>
                                <Badge variant={severity as 'default' | 'destructive' | 'secondary'}>
                                  {severity}
                                </Badge>
                              </div>
                            </CardHeader>
                            <CardContent>
                              <div className="space-y-4">
                                <div>
                                  <p className="font-medium mb-1">Description:</p>
                                  <p className="text-sm text-muted-foreground">{vuln.description}</p>
                                </div>
                                
                                {vuln.evidence && (
                                  <div>
                                    <p className="font-medium mb-1">Evidence:</p>
                                    <div className="text-sm text-muted-foreground space-y-2">
                                      {vuln.evidence.payload && (
                                        <p><span className="font-medium">Payload:</span> {vuln.evidence.payload}</p>
                                      )}
                                      {vuln.evidence.endpoints?.map((endpoint, i) => (
                                        <div key={i} className="pl-4 border-l-2 border-muted">
                                          <p><span className="font-medium">URL:</span> {endpoint.url}</p>
                                          <p><span className="font-medium">Method:</span> {endpoint.method}</p>
                                          <p><span className="font-medium">Status:</span> {endpoint.status}</p>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                )}

                                {vuln.remediation && (
                                  <div>
                                    <p className="font-medium mb-1">Remediation:</p>
                                    <p className="text-sm text-muted-foreground">{vuln.remediation}</p>
                                  </div>
                                )}

                                {(vuln.cvss_score || vuln.cve_id) && (
                                  <div className="flex gap-2">
                                    {vuln.cvss_score && (
                                      <Badge variant="outline">CVSS: {vuln.cvss_score}</Badge>
                                    )}
                                    {vuln.cve_id && (
                                      <Badge variant="outline">{vuln.cve_id}</Badge>
                                    )}
                                  </div>
                                )}
                              </div>
                            </CardContent>
                          </Card>
                        ))}
                      </div>
                    );
                  })}
                </div>
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </Card>
      </div>
    </div>
  )
}

// Make the page component a simple wrapper
export default function ReportDetailsPage({ params }: { params: { id: string } }) {
  return <ReportDetails id={params.id} />
} 