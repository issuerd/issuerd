// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useMemo } from 'react'
import { cn } from '@/lib/utils'

interface DurationPreset {
  label: string
  seconds: number
}

const PRESETS: DurationPreset[] = [
  { label: '5 minutes', seconds: 300 },
  { label: '15 minutes', seconds: 900 },
  { label: '30 minutes', seconds: 1800 },
  { label: '1 hour', seconds: 3600 },
  { label: '2 hours', seconds: 7200 },
  { label: '12 hours', seconds: 43200 },
  { label: '1 day', seconds: 86400 },
  { label: '7 days', seconds: 604800 },
  { label: '30 days', seconds: 2592000 },
  { label: 'Never', seconds: -1 },
]

interface FormDurationProps {
  label?: string
  value: number
  onChange: (seconds: number) => void
  error?: string
  helperText?: string
  disabled?: boolean
}

export default function FormDuration({
  label,
  value,
  onChange,
  error,
  helperText,
  disabled,
}: FormDurationProps) {
  const selectedPreset = useMemo(
    () => PRESETS.find((p) => p.seconds === value),
    [value]
  )

  return (
    <div className="flex flex-col gap-1.5">
      {label && (
        <label className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
          {label}
        </label>
      )}
      <div className="flex flex-wrap gap-2">
        {PRESETS.map((preset) => {
          const active = preset.seconds === value
          return (
            <button
              key={preset.seconds}
              type="button"
              disabled={disabled}
              onClick={() => onChange(preset.seconds)}
              className={cn(
                'px-3 py-1.5 rounded-lg text-xs font-medium border transition-all',
                active
                  ? 'bg-cyan-neon/10 border-cyan-neon/40 text-cyan-neon'
                  : 'bg-white/[0.03] border-border-custom text-text-secondary hover:border-border-hover hover:text-text-primary',
                disabled && 'opacity-50 cursor-not-allowed'
              )}
            >
              {preset.label}
            </button>
          )
        })}
      </div>
      {selectedPreset && selectedPreset.seconds > 0 && (
        <div className="text-xs text-text-tertiary">
          {selectedPreset.seconds} seconds
        </div>
      )}
      {error ? (
        <span className="text-xs text-alert-red">{error}</span>
      ) : helperText ? (
        <span className="text-xs text-text-tertiary">{helperText}</span>
      ) : null}
    </div>
  )
}
