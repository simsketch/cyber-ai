const API_BASE_URL = 'http://localhost:8000/api'

export interface ScanResult {
  scan_type: string
  timestamp: string
  results: {
    attack_surface?: {
      risk_level: string
      total_ips?: number
      total_nameservers?: number
      total_subdomains?: number
      total_open_ports?: number
      services_running?: string[]
      missing_security_headers?: string[]
      insecure_cookies?: number
      waf_effectiveness?: number
      sensitive_file_count?: number
      backup_file_count?: number
      total_vulnerabilities?: number
      vulnerability_types?: string[]
    }
    error?: string
    waf_detected?: boolean
    zone_transfer_vulnerable?: boolean
  }
}

export interface Scan {
  id: string
  results: ScanResult[]
}

export interface ScanRequest {
  target: string
  scanners?: string[]
}

export async function startScan(request: ScanRequest): Promise<{ status: string; results: ScanResult[] }> {
  const response = await fetch(`${API_BASE_URL}/scan`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(request),
  })

  if (!response.ok) {
    throw new Error('Failed to start scan')
  }

  return response.json()
}

export async function getScans(): Promise<{ scans: Scan[] }> {
  const response = await fetch(`${API_BASE_URL}/scans`)

  if (!response.ok) {
    throw new Error('Failed to fetch scans')
  }

  return response.json()
} 