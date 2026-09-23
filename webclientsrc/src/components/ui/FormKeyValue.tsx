// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { Plus, Trash2 } from 'lucide-react'

interface FormKeyValueProps {
  value: Record<string, string>
  onChange: (value: Record<string, string>) => void
  label?: string
  helperText?: string
  keyLabel?: string
  valueLabel?: string
  disabled?: boolean
}

export default function FormKeyValue({
  value,
  onChange,
  label,
  helperText,
  keyLabel = 'Key',
  valueLabel = 'Value',
  disabled = false,
}: FormKeyValueProps) {
  const entries = Object.entries(value)

  function updateEntry(index: number, newKey: string, newVal: string) {
    const newEntries = [...entries]
    newEntries[index] = [newKey, newVal]
    onChange(Object.fromEntries(newEntries))
  }

  function removeEntry(index: number) {
    const newEntries = entries.filter((_, i) => i !== index)
    onChange(Object.fromEntries(newEntries))
  }

  function addEntry() {
    onChange({ ...value, '': '' })
  }

  return (
    <div className="flex flex-col gap-1.5">
      {label && (
        <span className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
          {label}
        </span>
      )}
      <div className="flex flex-col gap-2">
        {entries.map(([k, v], idx) => (
          <div key={idx} className="flex items-center gap-2">
            <input
              type="text"
              value={k}
              disabled={disabled}
              onChange={(e) => updateEntry(idx, e.target.value, v)}
              placeholder={keyLabel}
              className="flex-1 h-10 px-3 bg-surface-card border border-border-custom rounded-lg text-sm text-text-primary placeholder:text-text-tertiary focus:border-cyan-neon focus:shadow-[0_0_0_3px_rgba(0,229,255,0.1)] outline-none transition-all"
            />
            <input
              type="text"
              value={v}
              disabled={disabled}
              onChange={(e) => updateEntry(idx, k, e.target.value)}
              placeholder={valueLabel}
              className="flex-1 h-10 px-3 bg-surface-card border border-border-custom rounded-lg text-sm text-text-primary placeholder:text-text-tertiary focus:border-cyan-neon focus:shadow-[0_0_0_3px_rgba(0,229,255,0.1)] outline-none transition-all"
            />
            {!disabled && (
              <button
                type="button"
                onClick={() => removeEntry(idx)}
                className="p-2 text-text-tertiary hover:text-alert-red hover:bg-alert-red/10 rounded-lg transition-colors delete-shake"
                aria-label="Remove row"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            )}
          </div>
        ))}
        {!disabled && (
          <button
            type="button"
            onClick={addEntry}
            className="inline-flex items-center gap-1.5 self-start px-3 py-2 text-sm text-cyan-neon hover:bg-cyan-neon/10 rounded-lg transition-colors"
          >
            <Plus className="w-4 h-4" />
            Add row
          </button>
        )}
      </div>
      {helperText && (
        <span className="text-xs text-text-tertiary">{helperText}</span>
      )}
    </div>
  )
}
