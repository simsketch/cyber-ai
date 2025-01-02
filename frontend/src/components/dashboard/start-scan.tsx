'use client'

import { useState } from 'react'
import { useUser } from '@clerk/nextjs'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { useToast } from '@/components/ui/use-toast'
import { startScan } from '@/lib/api/scans'

export function StartScan() {
  const { user } = useUser()
  const [target, setTarget] = useState('')
  const [isComprehensive, setIsComprehensive] = useState(false)
  const queryClient = useQueryClient()
  const { toast } = useToast()

  const mutation = useMutation({
    mutationFn: () => startScan(target, user?.id || '', isComprehensive),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      toast({
        title: 'Scan started',
        description: 'Your scan has been started successfully.',
      })
      setTarget('')
      setIsComprehensive(false)
    },
    onError: (error) => {
      toast({
        title: 'Error',
        description: 'Failed to start scan. Please try again.',
        variant: 'destructive',
      })
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!target) {
      toast({
        title: 'Error',
        description: 'Please enter a target URL.',
        variant: 'destructive',
      })
      return
    }
    if (!user?.id) {
      toast({
        title: 'Error',
        description: 'You must be logged in to start a scan.',
        variant: 'destructive',
      })
      return
    }
    mutation.mutate()
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Start New Scan</CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="target">Target URL</Label>
            <Input
              id="target"
              placeholder="https://example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
          </div>
          <div className="flex items-center space-x-2">
            <Switch
              id="comprehensive"
              checked={isComprehensive}
              onCheckedChange={setIsComprehensive}
            />
            <Label htmlFor="comprehensive">Comprehensive Scan</Label>
          </div>
          <Button type="submit" disabled={mutation.isPending}>
            {mutation.isPending ? 'Starting...' : 'Start Scan'}
          </Button>
        </form>
      </CardContent>
    </Card>
  )
} 