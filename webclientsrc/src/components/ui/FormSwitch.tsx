// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import React, { forwardRef, useId } from 'react'
import { cn } from '@/lib/utils'

interface FormSwitchProps {
  checked: boolean
  onChange: (checked: boolean) => void
  label?: string
  helperText?: string
  disabled?: boolean
  name?: string
}

const FormSwitch = forwardRef<HTMLInputElement, FormSwitchProps>(
  ({ checked, onChange, label, helperText, disabled = false, name }, ref) => {
    const id = useId()

    function handleKeyDown(e: React.KeyboardEvent) {
      if (e.key === ' ' || e.key === 'Enter') {
        e.preventDefault()
        if (!disabled) onChange(!checked)
      }
    }

    return (
      <div className={cn('flex items-start gap-3', disabled && 'opacity-50 cursor-not-allowed')}>
        <div className="relative inline-flex items-center">
          <input
            ref={ref}
            type="checkbox"
            id={id}
            name={name}
            checked={checked}
            disabled={disabled}
            onChange={(e) => onChange(e.target.checked)}
            className="sr-only"
            aria-checked={checked}
            role="switch"
          />
          <div
            className={cn(
              'w-11 h-6 rounded-full transition-colors duration-200 ease-smooth cursor-pointer',
              checked ? 'bg-cyan-neon' : 'bg-white/10'
            )}
            onClick={() => !disabled && onChange(!checked)}
            onKeyDown={handleKeyDown}
            tabIndex={disabled ? -1 : 0}
          >
            <div
              className={cn(
                'w-5 h-5 rounded-full bg-white shadow-md transform transition-transform duration-200 ease-spring mt-0.5 ml-0.5',
                checked ? 'translate-x-5' : 'translate-x-0'
              )}
            />
          </div>
        </div>
        <div className="flex flex-col gap-0.5">
          {label && (
            <label
              htmlFor={id}
              className="text-sm text-text-primary cursor-pointer select-none"
            >
              {label}
            </label>
          )}
          {helperText && (
            <span className="text-xs text-text-tertiary">{helperText}</span>
          )}
        </div>
      </div>
    )
  }
)

FormSwitch.displayName = 'FormSwitch'
export default FormSwitch
