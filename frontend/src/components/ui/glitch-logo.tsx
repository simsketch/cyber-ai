'use client'

import { cn } from "@/lib/utils"
import Image from "next/image"

interface GlitchLogoProps {
  className?: string
  loading?: boolean
}

export function GlitchLogo({ className, loading = false }: GlitchLogoProps) {
  return (
    <div className={cn("relative", className)}>
      <Image
        src="/zeroday-logo.png"
        alt="Cyber AI Logo"
        width={300}
        height={150}
        className={cn(
          "transition-all duration-100",
          loading ? "glitch-effect-continuous" : "glitch-effect"
        )}
      />
      <style jsx global>{`
        @keyframes glitch {
          0% {
            transform: translateX(0);
            filter: hue-rotate(0deg);
          }
          20% {
            transform: translateX(-2px);
            filter: hue-rotate(90deg);
          }
          40% {
            transform: translateX(2px);
            filter: hue-rotate(180deg);
          }
          60% {
            transform: translateX(-2px);
            filter: hue-rotate(270deg);
          }
          80% {
            transform: translateX(2px);
            filter: hue-rotate(360deg);
          }
          100% {
            transform: translateX(0);
            filter: hue-rotate(0deg);
          }
        }

        .glitch-effect {
          animation: glitch 0.4s linear infinite;
        }

        .glitch-effect-continuous {
          animation: glitch 0.2s linear infinite;
        }
      `}</style>
    </div>
  )
} 