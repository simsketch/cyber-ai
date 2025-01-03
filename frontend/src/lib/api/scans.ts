import { Scan, ScanResult, StartScanPayload } from '@/types/scans'
import { fetchAPI } from '@/lib/fetch-api'

export async function startScan(
  target: string,
  userId: string,
  isComprehensive = false
): Promise<Scan> {
  return fetchAPI('/api/v1/scans', {
    method: 'POST',
    userId,
    body: JSON.stringify({
      target,
      user_id: userId,
      comprehensive: isComprehensive
    })
  })
}

export async function getScans(userId: string): Promise<Scan[]> {
  try {
    console.log('[Scans API] Fetching scans for user:', userId)
    const scans = await fetchAPI('/api/v1/scans', {
      userId
    })
    console.log('[Scans API] Successfully fetched scans:', scans.length)
    return scans
  } catch (error) {
    console.error('[Scans API] Failed to fetch scans:', error)
    throw error
  }
}

export async function getScan(id: string, userId: string): Promise<ScanResult> {
  console.log('Fetching scan details:', id)
  try {
    const response = await fetchAPI(`/api/v1/scans/${id}`, {
      userId
    })
    console.log('Scan details response:', response)
    return response
  } catch (error) {
    console.error('Failed to fetch scan details:', error)
    throw error
  }
}

export async function cancelScan(id: string, userId: string): Promise<Scan> {
  return fetchAPI(`/api/v1/scans/${id}/cancel`, {
    method: 'POST',
    userId
  })
} 