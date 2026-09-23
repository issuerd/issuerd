// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { CheckCircle, XCircle, AlertTriangle, Info, X } from 'lucide-react'
import { useToastStore } from '@/stores/toastStore'
import type { ToastItem } from '@/stores/toastStore'

const iconMap = {
  success: CheckCircle,
  error: XCircle,
  warning: AlertTriangle,
  info: Info,
}

const colorMap = {
  success: 'text-matrix-green',
  error: 'text-alert-red',
  warning: 'text-amber',
  info: 'text-cyan-neon',
}

export default function Toast({ id, title, message, type }: ToastItem) {
  const dismissToast = useToastStore((s) => s.dismissToast)
  const Icon = iconMap[type]

  return (
    <div className="animate-toast-slide-in bg-surface-card border border-border-custom rounded-xl p-4 shadow-toast flex items-start gap-3 min-w-[320px]">
      <Icon className={`w-5 h-5 flex-shrink-0 mt-0.5 ${colorMap[type]}`} aria-hidden="true" />
      <div className="flex-1 min-w-0">
        <p className="text-sm font-semibold text-white">{title}</p>
        {message && <p className="text-xs text-text-secondary mt-1 whitespace-pre-line">{message}</p>}
      </div>
      <button onClick={() => dismissToast(id)} className="p-1 hover:bg-white/5 rounded transition-colors" aria-label="Dismiss notification">
        <X className="w-4 h-4 text-text-tertiary" aria-hidden="true" />
      </button>
    </div>
  )
}
