// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

const statusStyles: Record<string, string> = {
  active: 'bg-matrix-green/10 text-matrix-green',
  inactive: 'bg-alert-red/10 text-alert-red',
  pending: 'bg-amber/10 text-amber',
}

const dotColors: Record<string, string> = {
  active: 'bg-matrix-green',
  inactive: 'bg-alert-red',
  pending: 'bg-amber',
}

interface StatusBadgeProps {
  status: string
  className?: string
}

export default function StatusBadge({ status, className = '' }: StatusBadgeProps) {
  const normalized = status.toLowerCase()
  const style = statusStyles[normalized] ?? 'bg-white/5 text-text-secondary'
  const dot = dotColors[normalized] ?? 'bg-text-tertiary'

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold uppercase tracking-wider ${style} ${className}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${dot}`} />
      {status}
    </span>
  )
}
