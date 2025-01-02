'use client'

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { ResponsiveLine } from '@nivo/line'

const mockData = [
  {
    id: 'Risk Score',
    data: [
      { x: '2023-12-23', y: 65 },
      { x: '2023-12-24', y: 68 },
      { x: '2023-12-25', y: 72 },
      { x: '2023-12-26', y: 75 },
      { x: '2023-12-27', y: 71 },
      { x: '2023-12-28', y: 78 },
      { x: '2023-12-29', y: 82 },
    ],
  },
]

export function RiskScoreChart() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Risk Score Trend</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-[300px]">
          <ResponsiveLine
            data={mockData}
            margin={{ top: 20, right: 20, bottom: 40, left: 40 }}
            xScale={{
              type: 'time',
              format: '%Y-%m-%d',
              useUTC: false,
              precision: 'day',
            }}
            yScale={{
              type: 'linear',
              min: 0,
              max: 100,
            }}
            axisLeft={{
              tickSize: 0,
              tickPadding: 8,
              tickRotation: 0,
            }}
            axisBottom={{
              tickSize: 0,
              tickPadding: 8,
              tickRotation: -45,
              format: '%b %d',
            }}
            enablePoints={true}
            pointSize={6}
            pointColor="white"
            pointBorderWidth={2}
            pointBorderColor={{ from: 'serieColor' }}
            enableGridX={false}
            curve="monotoneX"
            enableArea={true}
            areaOpacity={0.15}
          />
        </div>
      </CardContent>
    </Card>
  )
} 