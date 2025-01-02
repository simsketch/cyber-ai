import { GlitchLogo } from "./glitch-logo"

interface LoadingSpinnerProps {
  suppressHydrationWarning?: boolean
}

export function LoadingSpinner({ suppressHydrationWarning }: LoadingSpinnerProps) {
  return (
    <GlitchLogo />
  )
} 