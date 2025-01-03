import { API_BASE_URL } from '@/config'

const TIMEOUT_MS = 30000 // 30 seconds
const MAX_RETRIES = 3
const INITIAL_BACKOFF_MS = 1000 // 1 second

interface FetchAPIOptions extends RequestInit {
  headers?: Record<string, string>
  userId?: string
}

async function fetchWithTimeout(url: string, options: FetchAPIOptions) {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => {
    console.log(`Request to ${url} timed out after ${TIMEOUT_MS}ms`)
    controller.abort('Request timed out')
  }, TIMEOUT_MS)

  try {
    console.log(`Making request to ${url}`)
    const response = await fetch(url, {
      ...options,
      signal: controller.signal
    })
    clearTimeout(timeoutId)
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`)
    }
    
    const data = await response.json()
    return data
  } catch (error) {
    clearTimeout(timeoutId)
    if (error instanceof Error) {
      if (error.name === 'AbortError') {
        throw new Error('Request timed out')
      }
      throw error
    }
    throw new Error('An unknown error occurred')
  } finally {
    if (timeoutId) {
      clearTimeout(timeoutId)
    }
  }
}

export async function fetchAPI<T = any>(
  path: string,
  options: FetchAPIOptions = {}
): Promise<T> {
  const userId = options.userId || options.headers?.['X-User-ID']

  if (!userId) {
    console.error('Authentication error: No user ID available')
    throw new Error('Not authenticated')
  }

  const defaultHeaders = {
    'Content-Type': 'application/json',
    'X-User-ID': userId,
    'Accept': 'application/json'
  }

  const mergedHeaders = {
    ...defaultHeaders,
    ...(options.headers || {}),
  }

  const finalUrl = `${API_BASE_URL}${path}`
  console.log('Making request to:', finalUrl)

  let lastError: Error | null = null
  
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      return await fetchWithTimeout(finalUrl, {
        ...options,
        headers: mergedHeaders
      })
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error))
      console.error(`Request failed (attempt ${attempt}/${MAX_RETRIES}):`, error)
      
      if (attempt === MAX_RETRIES) {
        throw lastError
      }
      
      // Wait before retrying with exponential backoff
      const backoffMs = Math.min(INITIAL_BACKOFF_MS * Math.pow(2, attempt - 1), 5000)
      await new Promise(resolve => setTimeout(resolve, backoffMs))
    }
  }
  
  throw lastError || new Error('Request failed after all retries')
}

export default {
  fetchAPI,
} 