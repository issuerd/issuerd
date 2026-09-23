// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { cn } from '@/lib/utils'

interface FormContextLineProps {
  text?: string | null
  className?: string
}

export default function FormContextLine({ text, className }: FormContextLineProps) {
  if (!text) return null

  return (
    <p className={cn('text-xs text-text-tertiary leading-relaxed', className)}>
      {text}
    </p>
  )
}
