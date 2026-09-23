// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { Search, X } from 'lucide-react'

interface SearchBarProps {
  placeholder?: string
  value?: string
  onChange?: (value: string) => void
  className?: string
}

export default function SearchBar({ placeholder = 'Search...', value = '', onChange, className = '' }: SearchBarProps) {
  return (
    <div className={`relative ${className}`}>
      <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-[18px] h-[18px] text-text-tertiary" />
      <input
        data-search-input
        type="text"
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange?.(e.target.value)}
        className="w-full h-11 pl-11 pr-20 bg-surface-card border border-border-custom rounded-xl text-sm text-text-primary placeholder:text-text-tertiary focus:border-cyan-neon focus:shadow-[0_0_0_3px_rgba(0,229,255,0.1)] transition-all outline-none"
      />
      {value && (
        <button
          onClick={() => onChange?.('')}
          className="absolute right-12 top-1/2 -translate-y-1/2 p-1 hover:bg-white/5 rounded"
        >
          <X className="w-4 h-4 text-text-tertiary" />
        </button>
      )}
      {!value && (
        <span className="absolute right-3 top-1/2 -translate-y-1/2 text-[11px] text-text-tertiary bg-white/5 px-1.5 py-0.5 rounded">
          Ctrl+K
        </span>
      )}
    </div>
  )
}
