import { Report } from '@/types/reports'
import { fetchAPI } from '@/lib/fetch-api'

export async function getReports(userId: string): Promise<Report[]> {
  console.log('Fetching reports for user:', userId)
  try {
    const response = await fetchAPI('/api/v1/reports', {
      userId,
      headers: {
        'X-User-ID': userId
      }
    })
    console.log('Reports response:', response)
    return response || []
  } catch (error) {
    console.error('Failed to fetch reports:', error)
    throw error
  }
}

export async function getReport(id: string, userId: string): Promise<Report> {
  console.log('Fetching report details:', id, 'for user:', userId)
  try {
    const response = await fetchAPI(`/api/v1/reports/${id}`, {
      userId,
      headers: {
        'X-User-ID': userId
      }
    })
    console.log('Report details response:', response)
    return response
  } catch (error) {
    console.error('Failed to fetch report details:', error)
    throw error
  }
} 