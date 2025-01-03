import { API_BASE_URL } from '@/config'

export async function fetchAPI(endpoint: string, options: RequestInit = {}) {
  const url = `${API_BASE_URL}${endpoint}`
  console.log(`[API Request] ${options.method || 'GET'} ${url}`)
  
  try {
    const response = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    })

    console.log(`[API Response] Status: ${response.status} ${response.statusText}`)
    
    if (!response.ok) {
      const errorData = await response.text()
      console.error(`[API Error] ${response.status}: ${errorData}`)
      throw new Error(`API error ${response.status}: ${errorData}`)
    }

    const data = await response.json()
    console.log('[API Success] Response received')
    return data
  } catch (error) {
    console.error('[API Error] Request failed:', error)
    if (error instanceof TypeError && error.message === 'Failed to fetch') {
      console.error('[API Error] Network error - Is the backend running?')
    }
    throw error
  }
} 