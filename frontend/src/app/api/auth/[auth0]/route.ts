import { handleAuth, handleLogin, handleCallback, handleProfile, handleLogout } from '@auth0/nextjs-auth0'
import { NextResponse } from 'next/server'
import type { NextApiRequest, NextApiResponse } from 'next'
import type { Session } from '@auth0/nextjs-auth0'

// Add CORS headers to all responses
const withCorsHeaders = (handler: any) => async (...args: any[]) => {
  try {
    const response = await handler(...args)
    const headers = new Headers(response.headers)
    
    headers.set('Access-Control-Allow-Origin', '*')
    headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
    headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    headers.set('Access-Control-Allow-Credentials', 'true')

    return new NextResponse(response.body, {
      status: response.status,
      headers,
    })
  } catch (error) {
    console.error('Auth error:', error)
    return new NextResponse(JSON.stringify({ error: 'Authentication error' }), {
      status: 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Allow-Credentials': 'true',
      },
    })
  }
}

// Create handlers for each auth route
const handlers = {
  login: handleLogin({
    returnTo: '/dashboard',
    authorizationParams: {
      audience: process.env.AUTH0_AUDIENCE,
      scope: process.env.AUTH0_SCOPE,
    },
  }),
  signup: handleLogin({
    returnTo: '/dashboard',
    authorizationParams: {
      screen_hint: 'signup',
      audience: process.env.AUTH0_AUDIENCE,
      scope: process.env.AUTH0_SCOPE,
    },
  }),
  callback: handleCallback({
    afterCallback: (_req: NextApiRequest, _res: NextApiResponse, session: Session) => {
      return session
    },
  }),
  logout: handleLogout({
    returnTo: '/',
  }),
  me: handleProfile(),
}

// Main handler that routes to the appropriate auth handler
export const GET = withCorsHeaders(async (request: Request, { params }: { params: { auth0: string } }) => {
  const handler = handlers[params.auth0 as keyof typeof handlers]
  if (!handler) {
    return new NextResponse(null, { status: 404 })
  }
  return handleAuth(handlers)(request)
})

// Handle OPTIONS requests for CORS
export async function OPTIONS() {
  return new NextResponse(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Credentials': 'true',
    },
  })
} 