// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { cn } from '@/lib/utils'

interface ClientsIllustrationProps {
  className?: string
}

export default function ClientsIllustration({ className }: ClientsIllustrationProps) {
  return (
    <svg
      viewBox="0 0 120 120"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={cn('w-24 h-24', className)}
      aria-hidden="true"
    >
      <rect
        x="24"
        y="20"
        width="72"
        height="80"
        rx="6"
        stroke="currentColor"
        strokeWidth="2"
        strokeDasharray="6 4"
      />
      <rect x="32" y="32" width="56" height="6" rx="2" fill="currentColor" fillOpacity="0.15" />
      <circle cx="42" cy="35" r="2" fill="currentColor" />
      <circle cx="50" cy="35" r="2" fill="currentColor" />
      <circle cx="58" cy="35" r="2" fill="currentColor" />
      <rect x="36" y="52" width="48" height="4" rx="1" fill="currentColor" fillOpacity="0.1" />
      <rect x="36" y="64" width="36" height="4" rx="1" fill="currentColor" fillOpacity="0.1" />
      <rect x="36" y="76" width="44" height="4" rx="1" fill="currentColor" fillOpacity="0.1" />
      <path d="M88 92l8 8m0-8l-8 8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
    </svg>
  )
}
