import Link from 'next/link'
import { UserNav } from '@/components/layout/user-button'
import { ModeToggle } from '@/components/mode-toggle'

export function Navbar() {
  return (
    <div className="border-b">
      <div className="flex h-16 items-center px-4">
        <Link href="/" className="flex items-center space-x-2">
          <span className="text-2xl font-bold">Cyber AI</span>
        </Link>
        <div className="ml-auto flex items-center space-x-4">
          <ModeToggle />
          <UserNav />
        </div>
      </div>
    </div>
  )
} 