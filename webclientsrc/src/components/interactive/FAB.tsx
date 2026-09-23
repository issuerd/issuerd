// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState } from 'react'
import { Plus } from 'lucide-react'

interface FABProps {
  label: string
  onClick: () => void
}

export default function FAB({ label, onClick }: FABProps) {
  const [showTooltip, setShowTooltip] = useState(false)

  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setShowTooltip(true)}
      onMouseLeave={() => setShowTooltip(false)}
      className="fixed bottom-8 right-8 z-fab w-14 h-14 bg-cyan-neon text-obsidian rounded-full shadow-fab flex items-center justify-center hover:scale-110 hover:shadow-[0_6px_30px_rgba(0,229,255,0.5)] active:scale-95 transition-all duration-200"
    >
      <Plus className="w-6 h-6" aria-hidden="true" />
      {showTooltip && (
        <span className="absolute right-full mr-3 px-3 py-1.5 bg-surface-card border border-border-custom rounded-lg text-xs text-text-primary whitespace-nowrap animate-fade-in">
          {label}
        </span>
      )}
    </button>
  )
}
