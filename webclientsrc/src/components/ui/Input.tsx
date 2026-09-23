// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import React, { forwardRef, useState, useId } from 'react'
import { cn } from '@/lib/utils'
import type { LucideIcon } from 'lucide-react'
import { Check, Copy } from 'lucide-react'

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string
  error?: string
  helperText?: string
  success?: boolean
  copyable?: boolean
  iconLeft?: LucideIcon
  iconRight?: LucideIcon
}

const Input = forwardRef<HTMLInputElement, InputProps>(
  (
    {
      label,
      error,
      helperText,
      success = false,
      copyable = false,
      iconLeft: IconLeft,
      iconRight: IconRight,
      className,
      maxLength,
      value,
      ...props
    },
    ref
  ) => {
    const generatedId = useId()
    const id = props.id || (props.name ? `input-${String(props.name)}` : generatedId)
    const errorId = `${id}-error`
    const helperId = `${id}-helper`
    const [copied, setCopied] = useState(false)

    const describedBy = [error ? errorId : undefined, helperText ? helperId : undefined]
      .filter(Boolean)
      .join(' ') || undefined

    const currentLength = typeof value === 'string' ? value.length : 0

    async function handleCopy() {
      const text = typeof value === 'string' ? value : props.defaultValue?.toString() ?? ''
      if (!text) return
      try {
        await navigator.clipboard.writeText(text)
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
      } catch {
        // ignore
      }
    }

    return (
      <div className={cn('flex flex-col gap-1.5', className)}>
        {label && (
          <label
            htmlFor={id}
            className="text-xs font-semibold uppercase tracking-wider text-muted-foreground"
          >
            {label}
          </label>
        )}
        <div className="relative">
          {IconLeft && (
            <div className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none">
              <IconLeft className="w-4 h-4" />
            </div>
          )}
          <input
            ref={ref}
            id={id}
            className={cn(
              'h-9 w-full min-w-0 rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-xs transition-[color,box-shadow] outline-none selection:bg-primary selection:text-primary-foreground file:inline-flex file:h-7 file:border-0 file:bg-transparent file:text-sm file:font-medium file:text-foreground placeholder:text-muted-foreground disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50 md:text-sm dark:bg-input/30',
              'focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50',
              error && 'border-destructive focus-visible:border-destructive focus-visible:ring-destructive/20 dark:focus-visible:ring-destructive/40',
              success && !error && 'border-em-600 focus-visible:border-em-600 focus-visible:ring-em-600/20',
              IconLeft && 'pl-10',
              (IconRight || copyable || success) && 'pr-10',
              copyable && 'font-mono'
            )}
            aria-invalid={!!error}
            aria-describedby={describedBy}
            maxLength={maxLength}
            value={value}
            {...props}
          />
          <div className="absolute right-3 top-1/2 -translate-y-1/2 flex items-center gap-1.5">
            {success && !error && <Check className="w-4 h-4 text-em-600" aria-hidden="true" />}
            {copyable && (
              <button
                type="button"
                onClick={handleCopy}
                className={cn(
                  'p-1 rounded transition-colors',
                  copied
                    ? 'text-em-600 bg-em-600/10'
                    : 'text-muted-foreground hover:text-foreground hover:bg-accent'
                )}
                aria-label={copied ? 'Copied' : 'Copy to clipboard'}
              >
                {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            )}
            {IconRight && !copyable && (
              <IconRight className="w-4 h-4 text-muted-foreground" aria-hidden="true" />
            )}
          </div>
        </div>
        <div className="flex items-center justify-between gap-2">
          {error ? (
            <span id={errorId} className="text-xs text-destructive">
              {error}
            </span>
          ) : helperText ? (
            <span id={helperId} className="text-xs text-muted-foreground">
              {helperText}
            </span>
          ) : (
            <span />
          )}
          {maxLength !== undefined && (
            <span className="text-xs text-muted-foreground tabular-nums">
              {currentLength}/{maxLength}
            </span>
          )}
        </div>
      </div>
    )
  }
)

Input.displayName = 'Input'
export default Input
