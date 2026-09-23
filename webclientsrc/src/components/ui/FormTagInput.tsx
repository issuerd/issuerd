// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import React, { useState, useRef, useId, KeyboardEvent } from 'react'
import { cn } from '@/lib/utils'
import { X } from 'lucide-react'

interface FormTagInputProps {
  tags: string[]
  onChange: (tags: string[]) => void
  label?: string
  placeholder?: string
  error?: string
  helperText?: string
  maxTags?: number
  disabled?: boolean
}

export default function FormTagInput({
  tags,
  onChange,
  label,
  placeholder = 'Type and press Enter...',
  error,
  helperText,
  maxTags,
  disabled = false,
}: FormTagInputProps) {
  const id = useId()
  const errorId = `${id}-error`
  const helperId = `${id}-helper`
  const [inputValue, setInputValue] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)

  const describedBy = [error ? errorId : undefined, helperText ? helperId : undefined]
    .filter(Boolean)
    .join(' ') || undefined

  function addTag(raw: string) {
    const trimmed = raw.trim()
    if (!trimmed) return
    if (maxTags !== undefined && tags.length >= maxTags) return
    if (tags.includes(trimmed)) return
    onChange([...tags, trimmed])
  }

  function removeTag(index: number) {
    onChange(tags.filter((_, i) => i !== index))
  }

  function handleKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault()
      addTag(inputValue)
      setInputValue('')
    } else if (e.key === 'Backspace' && inputValue === '' && tags.length > 0) {
      removeTag(tags.length - 1)
    }
  }

  function handlePaste(e: React.ClipboardEvent) {
    e.preventDefault()
    const pasted = e.clipboardData.getData('text')
    const parts = pasted.split(/[,\n]/).map((s) => s.trim()).filter(Boolean)
    const newTags = [...tags]
    for (const part of parts) {
      if (maxTags !== undefined && newTags.length >= maxTags) break
      if (!newTags.includes(part)) newTags.push(part)
    }
    onChange(newTags)
  }

  return (
    <div className="flex flex-col gap-1.5">
      {label && (
        <label
          htmlFor={id}
          className="text-xs font-semibold uppercase tracking-wider text-text-secondary"
        >
          {label}
        </label>
      )}
      <div
        className={cn(
          'min-h-[2.75rem] w-full px-2 py-1.5 bg-surface-card border border-border-custom rounded-lg text-sm text-text-primary focus-within:border-cyan-neon focus-within:shadow-[0_0_0_3px_rgba(0,229,255,0.1)] outline-none transition-all flex flex-wrap items-center gap-1.5',
          error && 'border-alert-red focus-within:border-alert-red focus-within:shadow-[0_0_0_3px_rgba(255,23,68,0.1)]',
          disabled && 'opacity-50 cursor-not-allowed'
        )}
        onClick={() => inputRef.current?.focus()}
      >
        {tags.map((tag, idx) => (
          <span
            key={`${tag}-${idx}`}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-cyan-neon/10 border border-cyan-neon/20 text-xs text-cyan-neon"
          >
            <span className="truncate max-w-[200px]" title={tag}>{tag}</span>
            {!disabled && (
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation()
                  removeTag(idx)
                }}
                className="p-0.5 rounded hover:bg-cyan-neon/20 transition-colors"
                aria-label={`Remove ${tag}`}
              >
                <X className="w-3 h-3" />
              </button>
            )}
          </span>
        ))}
        <input
          ref={inputRef}
          id={id}
          type="text"
          value={inputValue}
          disabled={disabled || (maxTags !== undefined && tags.length >= maxTags)}
          onChange={(e) => setInputValue(e.target.value)}
          onKeyDown={handleKeyDown}
          onPaste={handlePaste}
          onBlur={() => {
            if (inputValue.trim()) {
              addTag(inputValue)
              setInputValue('')
            }
          }}
          placeholder={tags.length === 0 ? placeholder : ''}
          className="flex-1 min-w-[80px] bg-transparent outline-none text-sm text-text-primary placeholder:text-text-tertiary h-7"
          aria-describedby={describedBy}
        />
      </div>
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
        {maxTags !== undefined && (
          <span className="text-xs text-text-tertiary tabular-nums">
            {tags.length}/{maxTags}
          </span>
        )}
      </div>
    </div>
  )
}
