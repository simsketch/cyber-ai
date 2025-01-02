'use client'

import * as React from 'react'
import { ClerkProvider } from '@clerk/nextjs'
import { dark } from '@clerk/themes'

export function AuthProvider({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <ClerkProvider
      publishableKey={process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY}
      appearance={{
        baseTheme: dark,
        elements: {
          card: "bg-background",
          formButtonPrimary: "bg-primary text-primary-foreground hover:bg-primary/90",
        }
      }}
    >
      {children}
    </ClerkProvider>
  )
} 