import { getSession } from '@auth0/nextjs-auth0'
import { NextApiRequest, NextApiResponse } from 'next'

export async function getAuthenticatedUser(req: NextApiRequest, res: NextApiResponse) {
  const session = await getSession(req, res)
  if (!session?.user) {
    throw new Error('Not authenticated')
  }
  return session.user
}

export function getAuthHeaders(token: string) {
  return {
    Authorization: `Bearer ${token}`,
  }
} 