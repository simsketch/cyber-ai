'use client'

import { useState } from 'react'
import { ResponsiveNetwork } from '@nivo/network'

type Node = {
  id: string
  name: string
  type: 'server' | 'client' | 'router' | 'switch'
  size: number
}

type Link = {
  source: string
  target: string
  distance: number
}

type NetworkData = {
  nodes: Node[]
  links: Link[]
}

const mockData: NetworkData = {
  nodes: [
    { id: 'router1', name: 'Main Router', type: 'router', size: 24 },
    { id: 'switch1', name: 'Core Switch', type: 'switch', size: 20 },
    { id: 'server1', name: 'Web Server', type: 'server', size: 16 },
    { id: 'server2', name: 'Database', type: 'server', size: 16 },
    { id: 'client1', name: 'Workstation 1', type: 'client', size: 12 },
    { id: 'client2', name: 'Workstation 2', type: 'client', size: 12 },
  ],
  links: [
    { source: 'router1', target: 'switch1', distance: 50 },
    { source: 'switch1', target: 'server1', distance: 30 },
    { source: 'switch1', target: 'server2', distance: 30 },
    { source: 'switch1', target: 'client1', distance: 20 },
    { source: 'switch1', target: 'client2', distance: 20 },
  ],
}

const nodeColors: Record<Node['type'], string> = {
  server: 'rgb(97, 205, 187)',
  client: 'rgb(244, 117, 96)',
  router: 'rgb(241, 225, 91)',
  switch: 'rgb(232, 193, 160)',
}

export function NetworkMap() {
  const [data] = useState<NetworkData>(mockData)

  return (
    <div className="h-[600px] rounded-lg border bg-background">
      <ResponsiveNetwork
        data={data}
        margin={{ top: 0, right: 0, bottom: 0, left: 0 }}
        linkDistance={(e: Link) => e.distance}
        centeringStrength={0.3}
        repulsivity={6}
        nodeSize={(n: Node) => n.size}
        activeNodeSize={(n: Node) => 1.5 * n.size}
        nodeColor={(e: Node) => nodeColors[e.type]}
        nodeBorderWidth={1}
        nodeBorderColor={{
          from: 'color',
          modifiers: [['darker', 0.8]],
        }}
        linkThickness={1}
        linkBlendMode="multiply"
        motionConfig="gentle"
      />
    </div>
  )
} 