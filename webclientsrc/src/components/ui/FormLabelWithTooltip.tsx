// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { HelpCircle } from 'lucide-react'
import { cn } from '@/lib/utils'
import Tooltip from './Tooltip'

interface FormLabelWithTooltipProps {
  label: string
  htmlFor?: string
  tooltipText?: string | null
  required?: boolean
  className?: string
}

export default function FormLabelWithTooltip({
  label,
  htmlFor,
  tooltipText,
  required = false,
  className,
}: FormLabelWithTooltipProps) {
  const labelContent = (
    <label
      htmlFor={htmlFor}
      className={cn(
        'text-xs font-semibold uppercase tracking-wider text-text-secondary inline-flex items-center gap-1.5',
        className
      )}
    >
      <span>{label}</span>
      {required && <span className="text-alert-red">*</span>}
    </label>
  )

  if (!tooltipText) return labelContent

  return (
    <div className="inline-flex items-center gap-1.5">
      {labelContent}
      <Tooltip content={tooltipText}>
        <span className="inline-flex items-center justify-center text-text-tertiary hover:text-cyan-neon transition-colors cursor-help">
          <HelpCircle className="w-3.5 h-3.5" aria-hidden="true" />
          <span className="sr-only">More info</span>
        </span>
      </Tooltip>
    </div>
  )
}
