'use client'

import { useUser } from '@auth0/nextjs-auth0/client'
import { Button } from '@/components/ui/button'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { User2 } from 'lucide-react'

export function UserNav() {
  const { user, isLoading } = useUser()

  if (isLoading) return null

  if (!user) {
    return (
      <Button variant="ghost" asChild>
        <a href="/api/auth/login">Sign In</a>
      </Button>
    )
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" className="relative h-9 w-9 rounded-full">
          <Avatar className="h-9 w-9">
            <AvatarImage src={user.picture || undefined} alt={user.name || 'User'} />
            <AvatarFallback>
              <User2 className="h-6 w-6" />
            </AvatarFallback>
          </Avatar>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem asChild>
          <a href="/api/auth/logout">Sign Out</a>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
} 