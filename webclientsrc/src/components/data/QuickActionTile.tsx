// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { cn } from '@/lib/utils'
import type { LucideIcon } from 'lucide-react'

interface QuickActionTileProps {
  label: string
  icon: LucideIcon
  onClick?: () => void
  href?: string
}

export default function QuickActionTile({ label, icon: Icon, onClick, href }: QuickActionTileProps) {
  const content = (
    <div
      className={cn(
        'flex flex-col items-center justify-center gap-3 p-5',
        'bg-surface-dark border border-border-custom rounded-xl',
        'transition-all duration-250 ease-smooth',
        'hover:border-cyan-neon/30 hover:shadow-glow-cyan hover:-translate-y-0.5',
        (onClick || href) && 'cursor-pointer'
      )}
    >
      <div className="w-10 h-10 rounded-lg bg-cyan-neon/10 flex items-center justify-center">
        <Icon className="w-5 h-5 text-cyan-neon" aria-hidden="true" />
      </div>
      <span className="text-sm font-medium text-text-secondary">{label}</span>
    </div>
  )

  if (href) {
    return <a href={href}>{content}</a>
  }
  if (onClick) {
    return <button onClick={onClick}>{content}</button>
  }
  return content
}
