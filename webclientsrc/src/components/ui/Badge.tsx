// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { cn } from '@/lib/utils'

interface BadgeProps {
  variant?: 'success' | 'warning' | 'danger' | 'info'
  children: React.ReactNode
  className?: string
}

export default function Badge({ variant = 'info', children, className }: BadgeProps) {
  const variants = {
    success: 'bg-em-500/10 text-em-600 border-em-500/20 dark:text-em-400',
    warning: 'bg-amber-500/10 text-amber-600 border-amber-500/20 dark:text-amber-400',
    danger: 'bg-red-500/10 text-red-600 border-red-500/20 dark:text-red-400',
    info: 'bg-blue-500/10 text-blue-600 border-blue-500/20 dark:text-blue-400',
  }

  return (
    <span className={cn('inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold uppercase tracking-wider border', variants[variant], className)}>
      {children}
    </span>
  )
}
