export type ScanStatus = 'pending' | 'in-progress' | 'completed' | 'failed'

export interface Vulnerability {
  title: string
  description: string
  severity: string
  remediation?: string
  cvss_score?: number
  cve_id?: string
}

export interface Scan {
  id: string
  target: string
  status: ScanStatus
  user_id: string
  vulnerabilities: Vulnerability[]
  total_vulnerabilities: number
  started_at: string | null
  completed_at: string | null
  error: string | null
  scan_type: string
  scan_options: Record<string, any>
  progress?: number
  message?: string
}

export interface StartScanPayload {
  target: string
  user_id: string
  scan_type?: string
  scan_options?: Record<string, any>
}

export interface ScanResult extends Scan {
  report?: {
    findings_summary: {
      high: number
      medium: number
      low: number
    }
  }
} 