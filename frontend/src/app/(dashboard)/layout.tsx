'use client'

import { Sidebar } from '@/components/layout/sidebar'
import { Footer } from '@/components/layout/footer'
import { QueryProvider } from '@/components/query-provider'
import { ThemeProvider } from '@/components/theme-provider'
import { Toaster } from '@/components/ui/toaster'

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <ThemeProvider attribute="class" defaultTheme="system" enableSystem>
      <QueryProvider>
        <div className="flex min-h-screen flex-col">
          <div className="flex flex-1">
            <Sidebar />
            <main className="flex-1 p-8">{children}</main>
          </div>
          <Footer />
        </div>
        <Toaster />
      </QueryProvider>
    </ThemeProvider>
  )
} 