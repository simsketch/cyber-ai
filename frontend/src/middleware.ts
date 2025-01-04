import { withMiddlewareAuthRequired } from '@auth0/nextjs-auth0/edge'
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

// Debug middleware to log auth information
export default withMiddlewareAuthRequired(async function middleware(req: NextRequest) {
  const res = NextResponse.next()

  // Add CORS headers
  res.headers.set('Access-Control-Allow-Origin', process.env.NEXT_PUBLIC_BASE_URL || 'http://localhost:3000')
  res.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
  res.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization')
  res.headers.set('Access-Control-Allow-Credentials', 'true')

  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    return new NextResponse(null, { 
      status: 200,
      headers: res.headers,
    })
  }

  console.log('\n[Auth Debug] ---- New Request ----')
  console.log('[Auth Debug] Request URL:', req.url)
  console.log('[Auth Debug] NextURL:', req.nextUrl.toString())
  console.log('[Auth Debug] Host:', req.headers.get('host'))
  console.log('[Auth Debug] Origin:', req.headers.get('origin'))
  console.log('[Auth Debug] Referer:', req.headers.get('referer'))
  
  // Log security-related headers
  console.log('[Auth Debug] Security Headers:', {
    'x-forwarded-proto': req.headers.get('x-forwarded-proto'),
    'x-forwarded-host': req.headers.get('x-forwarded-host'),
  })

  return res
})

export const config = {
  matcher: [
    // Skip auth for public routes and API routes
    '/((?!api/auth|_next/static|_next/image|favicon.ico|$).*)',
  ],
} 