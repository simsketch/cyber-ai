export interface Report {
  _id: string
  title: string
  type: string
  description: string
  generated_at: string
  user_id: string
  scan_ids: string[]
  ai_summary?: string
  markdown_content?: string
  health_score?: number
  health_rating?: string
  scan_duration?: number
  data: {
    scan_id: string
    target: string
    total_vulnerabilities: number
    vulnerabilities: Array<{
      title: string
      description: string
      severity: 'high' | 'medium' | 'low'
      cvss_score?: number
      cve_id?: string
      remediation?: string
    }>
    findings_summary: {
      high: number
      medium: number
      low: number
    }
  }
} 