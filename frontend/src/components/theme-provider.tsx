'use client'

import { createContext, useContext } from 'react'
import { ThemeProvider as NextThemesProvider } from 'next-themes'

const ThemeProviderContext = createContext<{
  theme: string
  setTheme: (theme: string) => void
}>({
  theme: 'system',
  setTheme: () => null,
})

interface ThemeProviderProps {
  children: React.ReactNode
  [key: string]: any
}

export function ThemeProvider({ children, ...props }: ThemeProviderProps) {
  return (
    <NextThemesProvider
      attribute="class"
      defaultTheme="dark"
      enableSystem
      {...props}
    >
      {children}
    </NextThemesProvider>
  )
}

export const useTheme = () => {
  const context = useContext(ThemeProviderContext)

  if (context === undefined)
    throw new Error('useTheme must be used within a ThemeProvider')

  return context
} 