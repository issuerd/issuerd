// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import type { EnumValueRepresentation } from '@generated'
import { useEnumDescription } from '../../hooks/useEnumDescription'
import { cn } from '@/lib/utils'
import Tooltip from './Tooltip'

interface EnumBadgeProps {
  enumList: EnumValueRepresentation[] | undefined
  value: string | null | undefined
  fallback?: string
  className?: string
}

export default function EnumBadge({
  enumList,
  value,
  fallback,
  className,
}: EnumBadgeProps) {
  const entry = useEnumDescription(enumList, value)
  const label = entry?.name ?? fallback ?? value ?? '—'
  const description = entry?.description

  if (!description) {
    return (
      <span className={cn(
        'inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold uppercase tracking-wider',
        'bg-cyan-neon/10 text-cyan-neon border border-cyan-neon/20',
        className
      )}>
        {label}
      </span>
    )
  }

  return (
    <Tooltip content={description}>
      <span className={cn(
        'inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold uppercase tracking-wider cursor-help',
        'bg-cyan-neon/10 text-cyan-neon border border-cyan-neon/20',
        className
      )}>
        {label}
      </span>
    </Tooltip>
  )
}
