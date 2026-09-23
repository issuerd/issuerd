// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { Area, AreaChart, ResponsiveContainer, YAxis } from 'recharts'
import { cn } from '@/lib/utils'

interface SparklineProps {
  data: number[]
  trend?: 'up' | 'down' | 'neutral'
  color?: string
  className?: string
}

export default function Sparkline({
  data,
  trend = 'neutral',
  color,
  className,
}: SparklineProps) {
  const strokeColor =
    color ?? (trend === 'up' ? '#00e676' : trend === 'down' ? '#ff1744' : '#00e5ff')
  const chartData = data.map((value, index) => ({ index, value }))

  return (
    <div className={cn('w-[120px] h-[40px]', className)}>
      <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={0}>
        <AreaChart data={chartData} margin={{ top: 2, right: 2, bottom: 2, left: 2 }}>
          <defs>
            <linearGradient id={`sparkline-gradient-${trend}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={strokeColor} stopOpacity={0.3} />
              <stop offset="100%" stopColor={strokeColor} stopOpacity={0} />
            </linearGradient>
          </defs>
          <YAxis domain={['dataMin', 'dataMax']} hide />
          <Area
            type="monotone"
            dataKey="value"
            stroke={strokeColor}
            strokeWidth={2}
            fill={`url(#sparkline-gradient-${trend})`}
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
