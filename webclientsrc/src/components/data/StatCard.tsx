// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { cn } from '@/lib/utils'
import { ArrowUpRight, ArrowDownRight, Minus } from 'lucide-react'
import Sparkline from './Sparkline'
import type { LucideIcon } from 'lucide-react'

interface StatCardProps {
  title: string
  value: string | number
  trend?: 'up' | 'down' | 'neutral'
  trendLabel?: string
  sparklineData?: number[]
  icon: LucideIcon
  href?: string
  loading?: boolean
}

export default function StatCard({
  title,
  value,
  trend = 'neutral',
  trendLabel,
  sparklineData,
  icon: Icon,
  href,
  loading,
}: StatCardProps) {
  const TrendIcon = trend === 'up' ? ArrowUpRight : trend === 'down' ? ArrowDownRight : Minus
  const trendColor =
    trend === 'up' ? 'text-matrix-green' : trend === 'down' ? 'text-alert-red' : 'text-text-tertiary'

  const content = (
    <div
      className={cn(
        'relative bg-surface-dark border border-border-custom rounded-xl p-5 overflow-hidden group',
        'transition-all duration-250 ease-smooth',
        href && 'hover:border-cyan-neon/30 hover:shadow-glow-cyan cursor-pointer card-hover-lift'
      )}
    >
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2 text-text-secondary">
          <Icon className="w-4 h-4" aria-hidden="true" />
          <span className="text-xs font-semibold uppercase tracking-wider">{title}</span>
        </div>
        {sparklineData && <Sparkline data={sparklineData} trend={trend} />}
      </div>

      {loading ? (
        <div className="h-10 w-24 bg-white/5 rounded animate-pulse" />
      ) : (
        <div className="text-3xl font-display font-semibold text-text-primary">{value}</div>
      )}

      {trendLabel && !loading && (
        <div className={cn('flex items-center gap-1 mt-2 text-xs font-medium', trendColor)}>
          <TrendIcon className="w-3.5 h-3.5" aria-hidden="true" />
          {trendLabel}
        </div>
      )}
    </div>
  )

  if (href) {
    return (
      <a href={href} className="block">
        {content}
      </a>
    )
  }

  return content
}
