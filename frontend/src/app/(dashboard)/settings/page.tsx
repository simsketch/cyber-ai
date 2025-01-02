import { DashboardHeader } from '@/components/dashboard/header'
import { DashboardShell } from '@/components/dashboard/shell'
import { SettingsForm } from '@/components/settings/settings-form'

export const metadata = {
  title: 'Settings - Cyber AI',
  description: 'Manage your security scanning settings and preferences',
}

export default function SettingsPage() {
  return (
    <DashboardShell>
      <DashboardHeader
        heading="Settings"
        text="Manage your security scanning settings and preferences"
      />
      <div className="grid gap-4">
        <SettingsForm />
      </div>
    </DashboardShell>
  )
} 