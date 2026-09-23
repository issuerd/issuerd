// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import React, { forwardRef, useId, useEffect, useRef } from 'react'
import { cn } from '@/lib/utils'

interface FormTextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string
  error?: string
  helperText?: string
  autoResize?: boolean
  monospace?: boolean
}

const FormTextarea = forwardRef<HTMLTextAreaElement, FormTextareaProps>(
  ({ label, error, helperText, autoResize = false, monospace = false, className, rows = 3, ...props }, ref) => {
    const generatedId = useId()
    const id = props.id || (props.name ? `textarea-${String(props.name)}` : generatedId)
    const errorId = `${id}-error`
    const helperId = `${id}-helper`
    const innerRef = useRef<HTMLTextAreaElement | null>(null)

    const describedBy = [error ? errorId : undefined, helperText ? helperId : undefined]
      .filter(Boolean)
      .join(' ') || undefined

    useEffect(() => {
      if (!autoResize) return
      const el = innerRef.current
      if (!el) return
      el.style.height = 'auto'
      el.style.height = `${el.scrollHeight}px`
    }, [autoResize, props.value])

    function setRefs(el: HTMLTextAreaElement | null) {
      innerRef.current = el
      if (typeof ref === 'function') {
        ref(el)
      } else if (ref) {
        ref.current = el
      }
    }

    return (
      <div className={cn('flex flex-col gap-1.5', className)}>
        {label && (
          <label
            htmlFor={id}
            className="text-xs font-semibold uppercase tracking-wider text-text-secondary"
          >
            {label}
          </label>
        )}
        <textarea
          ref={setRefs}
          id={id}
          rows={rows}
          className={cn(
            'w-full px-3 py-2 bg-surface-card border border-border-custom rounded-lg text-sm text-text-primary placeholder:text-text-tertiary focus:border-cyan-neon focus:shadow-[0_0_0_3px_rgba(0,229,255,0.1)] outline-none transition-all resize-y',
            error && 'border-alert-red focus:border-alert-red focus:shadow-[0_0_0_3px_rgba(255,23,68,0.1)]',
            monospace && 'font-mono text-xs',
            autoResize && 'resize-none overflow-hidden'
          )}
          aria-invalid={!!error}
          aria-describedby={describedBy}
          {...props}
        />
        <div className="flex items-center justify-between gap-2">
          {error ? (
            <span id={errorId} className="text-xs text-alert-red">
              {error}
            </span>
          ) : helperText ? (
            <span id={helperId} className="text-xs text-text-tertiary">
              {helperText}
            </span>
          ) : (
            <span />
          )}
        </div>
      </div>
    )
  }
)

FormTextarea.displayName = 'FormTextarea'
export default FormTextarea
