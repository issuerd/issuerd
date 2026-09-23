// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import React, { useState, useRef, useEffect, useId, useCallback } from 'react'
import { createPortal } from 'react-dom'
import { cn } from '@/lib/utils'
import { ChevronDown, Check, Search } from 'lucide-react'

export interface SelectOption {
  value: string
  label: string
  group?: string
  description?: string | null
}

interface FormSelectProps {
  options: SelectOption[]
  value?: string
  onChange: (value: string) => void
  label?: string
  placeholder?: string
  error?: string
  helperText?: string
  disabled?: boolean
  searchable?: boolean
  name?: string
}

export default function FormSelect({
  options,
  value,
  onChange,
  label,
  placeholder = 'Select...',
  error,
  helperText,
  disabled = false,
  searchable = false,
  name,
}: FormSelectProps) {
  const id = useId()
  const errorId = `${id}-error`
  const helperId = `${id}-helper`
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState('')
  const [highlightedIndex, setHighlightedIndex] = useState(0)
  const containerRef = useRef<HTMLDivElement>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const dropdownRef = useRef<HTMLDivElement>(null)
  const searchRef = useRef<HTMLInputElement>(null)
  const [dropdownStyle, setDropdownStyle] = useState<React.CSSProperties>({})

  const selectedOption = options.find((o) => o.value === value)

  const filteredOptions = search
    ? options.filter(
        (o) =>
          o.label.toLowerCase().includes(search.toLowerCase()) ||
          o.value.toLowerCase().includes(search.toLowerCase())
      )
    : options

  const groups = Array.from(new Set(filteredOptions.map((o) => o.group).filter(Boolean)))

  const describedBy = [error ? errorId : undefined, helperText ? helperId : undefined]
    .filter(Boolean)
    .join(' ') || undefined

  useEffect(() => {
    function onClickOutside(e: MouseEvent) {
      const target = e.target as Node
      if (containerRef.current?.contains(target) || dropdownRef.current?.contains(target)) {
        return
      }
      setOpen(false)
    }
    document.addEventListener('mousedown', onClickOutside)
    return () => document.removeEventListener('mousedown', onClickOutside)
  }, [])

  // The dropdown is portaled to document.body so it escapes clipping
  // ancestors (e.g. a Modal's overflow-y-auto body). Track the trigger's
  // viewport position; flip above the trigger when there is more room there.
  const updateDropdownPosition = useCallback(() => {
    const rect = triggerRef.current?.getBoundingClientRect()
    if (!rect) return
    const maxHeight = 240
    const gap = 4
    const spaceBelow = window.innerHeight - rect.bottom - gap
    const openUp = spaceBelow < maxHeight && rect.top - gap > spaceBelow
    const style: React.CSSProperties = openUp
      ? {
          left: rect.left,
          width: rect.width,
          bottom: window.innerHeight - rect.top + gap,
          maxHeight: Math.min(maxHeight, rect.top - gap),
        }
      : {
          left: rect.left,
          width: rect.width,
          top: rect.bottom + gap,
          maxHeight: Math.min(maxHeight, spaceBelow),
        }
    setDropdownStyle(style)
  }, [])

  useEffect(() => {
    if (!open) return
    updateDropdownPosition()
    window.addEventListener('resize', updateDropdownPosition)
    document.addEventListener('scroll', updateDropdownPosition, true)
    return () => {
      window.removeEventListener('resize', updateDropdownPosition)
      document.removeEventListener('scroll', updateDropdownPosition, true)
    }
  }, [open, updateDropdownPosition])

  useEffect(() => {
    if (open && searchable && searchRef.current) {
      searchRef.current.focus()
    }
  }, [open, searchable])

  useEffect(() => {
    setHighlightedIndex(0)
  }, [search, filteredOptions.length])

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (!open) {
        if (e.key === 'Enter' || e.key === ' ' || e.key === 'ArrowDown') {
          e.preventDefault()
          setOpen(true)
        }
        return
      }

      switch (e.key) {
        case 'ArrowDown':
          e.preventDefault()
          setHighlightedIndex((i) => Math.min(i + 1, filteredOptions.length - 1))
          break
        case 'ArrowUp':
          e.preventDefault()
          setHighlightedIndex((i) => Math.max(i - 1, 0))
          break
        case 'Enter':
          e.preventDefault()
          if (filteredOptions[highlightedIndex]) {
            onChange(filteredOptions[highlightedIndex].value)
            setOpen(false)
            setSearch('')
          }
          break
        case 'Escape':
          e.preventDefault()
          setOpen(false)
          setSearch('')
          break
        case 'Tab':
          setOpen(false)
          setSearch('')
          break
      }
    },
    [open, filteredOptions, highlightedIndex, onChange]
  )

  function selectOption(option: SelectOption) {
    onChange(option.value)
    setOpen(false)
    setSearch('')
  }

  return (
    <div className="flex flex-col gap-1.5" ref={containerRef}>
      {label && (
        <label
          htmlFor={id}
          className="text-xs font-semibold uppercase tracking-wider text-text-secondary"
        >
          {label}
        </label>
      )}
      <div className="relative">
        <button
          ref={triggerRef}
          id={id}
          name={name}
          type="button"
          disabled={disabled}
          onClick={() => setOpen((o) => !o)}
          onKeyDown={handleKeyDown}
          className={cn(
            'w-full h-11 px-3 bg-surface-card border border-border-custom rounded-lg text-sm text-left text-text-primary focus:border-cyan-neon focus:shadow-[0_0_0_3px_rgba(0,229,255,0.1)] outline-none transition-all flex items-center justify-between',
            error && 'border-alert-red focus:border-alert-red focus:shadow-[0_0_0_3px_rgba(255,23,68,0.1)]',
            disabled && 'opacity-50 cursor-not-allowed',
            !selectedOption && 'text-text-tertiary'
          )}
          aria-haspopup="listbox"
          aria-expanded={open}
          aria-describedby={describedBy}
        >
          <span className="truncate">{selectedOption?.label ?? placeholder}</span>
          <ChevronDown
            className={cn(
              'w-4 h-4 text-text-tertiary transition-transform duration-200 shrink-0 ml-2',
              open && 'rotate-180'
            )}
          />
        </button>

        {open &&
          createPortal(
            <div
              ref={dropdownRef}
              className="fixed z-dropdown bg-surface-dark border border-border-custom rounded-lg shadow-modal overflow-hidden"
              style={dropdownStyle}
              role="listbox"
            >
            {searchable && (
              <div className="px-3 py-2 border-b border-border-custom">
                <div className="relative">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-tertiary" />
                  <input
                    ref={searchRef}
                    type="text"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder="Search..."
                    className="w-full h-8 pl-8 pr-3 bg-surface-card border border-border-custom rounded-md text-sm text-text-primary placeholder:text-text-tertiary focus:border-cyan-neon outline-none"
                  />
                </div>
              </div>
            )}
            <div className="max-h-60 overflow-auto py-1">
              {groups.length > 0 && !search
                ? groups.map((group) => (
                    <div key={group}>
                      <div className="px-3 py-1.5 text-xs font-semibold uppercase tracking-wider text-text-tertiary">
                        {group}
                      </div>
                      {filteredOptions
                        .filter((o) => o.group === group)
                        .map((option) => {
                          const globalIndex = filteredOptions.indexOf(option)
                          const isSelected = option.value === value
                          const isHighlighted = globalIndex === highlightedIndex
                          return (
                            <div
                              key={option.value}
                              role="option"
                              aria-selected={isSelected}
                              onClick={() => selectOption(option)}
                              onMouseEnter={() => setHighlightedIndex(globalIndex)}
                              title={option.description ?? undefined}
                              className={cn(
                                'px-3 py-2 text-sm cursor-pointer flex items-center justify-between transition-colors',
                                isHighlighted && 'bg-white/5',
                                isSelected && 'text-cyan-neon'
                              )}
                            >
                              <div className="flex flex-col">
                                <span>{option.label}</span>
                                {option.description && (
                                  <span className="text-[11px] text-text-tertiary leading-tight">{option.description}</span>
                                )}
                              </div>
                              {isSelected && <Check className="w-4 h-4 shrink-0 ml-2" />}
                            </div>
                          )
                        })}
                    </div>
                  ))
                : filteredOptions.map((option, idx) => {
                    const isSelected = option.value === value
                    const isHighlighted = idx === highlightedIndex
                    return (
                      <div
                        key={option.value}
                        role="option"
                        aria-selected={isSelected}
                        onClick={() => selectOption(option)}
                        onMouseEnter={() => setHighlightedIndex(idx)}
                        title={option.description ?? undefined}
                        className={cn(
                          'px-3 py-2 text-sm cursor-pointer flex items-center justify-between transition-colors',
                          isHighlighted && 'bg-white/5',
                          isSelected && 'text-cyan-neon'
                        )}
                      >
                        <div className="flex flex-col">
                          <span>{option.label}</span>
                          {option.description && (
                            <span className="text-[11px] text-text-tertiary leading-tight">{option.description}</span>
                          )}
                        </div>
                        {isSelected && <Check className="w-4 h-4 shrink-0 ml-2" />}
                      </div>
                    )
                  })}
              {filteredOptions.length === 0 && (
                <div className="px-3 py-2 text-sm text-text-tertiary">No results</div>
              )}
            </div>
            </div>,
            document.body
          )}
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
      </div>
    </div>
  )
}
