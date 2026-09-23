// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import type { EnumValueRepresentation } from '@generated'
import { useEnumDescription } from '../../hooks/useEnumDescription'
import Tooltip, { type TooltipPlacement } from './Tooltip'

interface EnumTooltipProps {
  enumList: EnumValueRepresentation[] | undefined
  value: string | null | undefined
  fallback?: string
  children: React.ReactElement
  placement?: TooltipPlacement
}

export default function EnumTooltip({
  enumList,
  value,
  fallback,
  children,
  placement = 'top',
}: EnumTooltipProps) {
  const entry = useEnumDescription(enumList, value)
  const content = entry?.description ?? fallback

  if (!content) return children

  return (
    <Tooltip content={content} placement={placement}>
      {children}
    </Tooltip>
  )
}
