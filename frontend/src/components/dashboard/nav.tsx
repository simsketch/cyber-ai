import Link from "next/link"
import { usePathname } from "next/navigation"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { BarChart, Shield, FileText } from "lucide-react"

export function DashboardNav() {
  const pathname = usePathname()

  const items = [
    {
      title: "Overview",
      href: "/",
      icon: BarChart
    },
    {
      title: "Scans",
      href: "/scans",
      icon: Shield
    },
    {
      title: "Reports",
      href: "/reports",
      icon: FileText
    },
    {
      title: "CVE Database",
      href: "/cve",
      icon: Shield
    }
  ]

  return (
    <nav className="grid items-start gap-2">
      {items.map((item, index) => {
        const Icon = item.icon
        return (
          <Link key={index} href={item.href}>
            <span className={cn(
              "group flex items-center rounded-md px-3 py-2 text-sm font-medium hover:bg-accent hover:text-accent-foreground",
              pathname === item.href ? "bg-accent" : "transparent",
            )}>
              <Icon className="mr-2 h-4 w-4" />
              <span>{item.title}</span>
            </span>
          </Link>
        )
      })}
    </nav>
  )
} 