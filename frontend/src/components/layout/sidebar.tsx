'use client'

import Link from 'next/link'
import { usePathname, useRouter } from 'next/navigation'
import { cn } from '@/lib/utils'
import {
  BarChart3,
  Shield,
  AlertTriangle,
  FileText,
  Settings,
  Network,
  Search,
  Database
} from 'lucide-react'
import Image from 'next/image'
const navigation = [
  {
    name: 'Dashboard',
    href: '/dashboard',
    icon: BarChart3,
  },
  {
    name: 'Scans',
    href: '/scans',
    icon: Search,
  },
  {
    name: 'Vulnerabilities',
    href: '/vulnerabilities',
    icon: AlertTriangle,
  },
  {
    name: 'Network',
    href: '/network',
    icon: Network,
  },
  {
    name: 'Reports',
    href: '/reports',
    icon: FileText,
  },
  {
    name: 'CVE Database',
    href: '/cve',
    icon: Database,
  },
  {
    name: 'Security Controls',
    href: '/controls',
    icon: Shield,
  },
  {
    name: 'Settings',
    href: '/settings',
    icon: Settings,
  },
]

export function Sidebar() {
  const router = useRouter()
  const pathname = usePathname()
  const handleLogoClick = (e: React.MouseEvent) => {
    e.preventDefault();
    const logo = e.currentTarget as HTMLElement;
    logo.classList.add('disappearing');
    
    setTimeout(() => {
      router.push('/dashboard');
    }, 500); // Match animation duration
  };

  return (
    <div className="flex h-screen w-64 flex-col border-r bg-background">
      <div className="flex flex-1 flex-col overflow-y-auto pt-5 pb-4">
          <Link href="/" className="flex items-center space-x-2">
            <Image
              src="/zeroday-logo.png"
              alt="ZeroDay Logo"
              width={150}
              height={40}
              className="dark:invert ml-11 logo"
              style={{ filter: 'invert(0)' }}
              onClick={handleLogoClick}
            />
          </Link>
        <nav className="mt-5 flex-1 space-y-1 px-2">
          {navigation.map((item) => {
            const isActive = pathname === item.href
            return (
              <Link
                key={item.name}
                href={item.href}
                className={cn(
                  'group flex items-center rounded-md px-2 py-2 text-sm font-medium',
                  isActive
                    ? 'bg-primary text-primary-foreground'
                    : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
                )}
              >
                <item.icon
                  className={cn(
                    'mr-3 h-5 w-5 flex-shrink-0',
                    isActive
                      ? 'text-primary-foreground'
                      : 'text-muted-foreground group-hover:text-accent-foreground'
                  )}
                  aria-hidden="true"
                />
                {item.name}
              </Link>
            )
          })}
        </nav>
      </div>
    </div>
  )
} 