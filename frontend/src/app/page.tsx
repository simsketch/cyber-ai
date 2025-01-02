'use client'

import { useRouter } from 'next/navigation'
import { useEffect } from 'react'
import { GlitchLogo } from '@/components/ui/glitch-logo'

export default function Home() {
  const router = useRouter()

  useEffect(() => {
    router.push('/dashboard')
  }, [router])

  return <GlitchLogo />
}
