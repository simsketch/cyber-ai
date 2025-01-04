import { handleAuth, handleLogin } from '@auth0/nextjs-auth0'
import { NextResponse } from 'next/server'

// Add CORS headers to all responses
const withCorsHeaders = (handler: any) => async (...args: any[]) => {
  const response = await handler(...args)
  const headers = new Headers(response.headers)
  
  headers.set('Access-Control-Allow-Origin', process.env.NEXT_PUBLIC_BASE_URL || 'http://localhost:3000')
  headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
  headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization')
  headers.set('Access-Control-Allow-Credentials', 'true')

  return new NextResponse(response.body, {
    status: response.status,
    headers,
  })
}

export const GET = withCorsHeaders(handleAuth({
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
}))

// Handle OPTIONS requests for CORS
export async function OPTIONS() {
  const response = new NextResponse(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': process.env.NEXT_PUBLIC_BASE_URL || 'http://localhost:3000',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Credentials': 'true',
    },
  })
  return response
} 