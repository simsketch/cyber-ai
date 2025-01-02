'use client'

import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'

type Settings = {
  scanInterval: number
  enableNotifications: boolean
  apiKey: string
  webhookUrl: string
}

const defaultSettings: Settings = {
  scanInterval: 24,
  enableNotifications: true,
  apiKey: '',
  webhookUrl: '',
}

export function SettingsForm() {
  const [settings, setSettings] = useState<Settings>(defaultSettings)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    // TODO: Save settings
    console.log('Saving settings:', settings)
  }

  return (
    <form onSubmit={handleSubmit}>
      <Card>
        <CardHeader>
          <CardTitle>Scan Settings</CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-2">
            <Label htmlFor="scanInterval">Scan Interval (hours)</Label>
            <Input
              id="scanInterval"
              type="number"
              min={1}
              max={168}
              value={settings.scanInterval}
              onChange={(e) =>
                setSettings({
                  ...settings,
                  scanInterval: parseInt(e.target.value),
                })
              }
            />
          </div>
          <div className="flex items-center space-x-2">
            <Switch
              id="notifications"
              checked={settings.enableNotifications}
              onCheckedChange={(checked: boolean) =>
                setSettings({ ...settings, enableNotifications: checked })
              }
            />
            <Label htmlFor="notifications">Enable Notifications</Label>
          </div>
          <div className="space-y-2">
            <Label htmlFor="apiKey">API Key</Label>
            <Input
              id="apiKey"
              type="password"
              value={settings.apiKey}
              onChange={(e) =>
                setSettings({ ...settings, apiKey: e.target.value })
              }
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="webhookUrl">Webhook URL</Label>
            <Input
              id="webhookUrl"
              type="url"
              value={settings.webhookUrl}
              onChange={(e) =>
                setSettings({ ...settings, webhookUrl: e.target.value })
              }
            />
          </div>
          <Button type="submit">Save Settings</Button>
        </CardContent>
      </Card>
    </form>
  )
} 