// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { cn } from '@/lib/utils'

interface EventsIllustrationProps {
  className?: string
}

export default function EventsIllustration({ className }: EventsIllustrationProps) {
  return (
    <svg
      viewBox="0 0 120 120"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={cn('w-24 h-24', className)}
      aria-hidden="true"
    >
      <path
        d="M28 24h64c4.418 0 8 3.582 8 8v64c0 4.418-3.582 8-8 8H28c-4.418 0-8-3.582-8-8V32c0-4.418 3.582-8 8-8z"
        stroke="currentColor"
        strokeWidth="2"
      />
      <path d="M24 40h72" stroke="currentColor" strokeWidth="2" />
      <rect x="34" y="54" width="52" height="4" rx="1" fill="currentColor" fillOpacity="0.12" />
      <rect x="34" y="66" width="40" height="4" rx="1" fill="currentColor" fillOpacity="0.12" />
      <rect x="34" y="78" width="48" height="4" rx="1" fill="currentColor" fillOpacity="0.12" />
      <circle cx="92" cy="88" r="10" stroke="currentColor" strokeWidth="2" />
      <path d="M88 88l3 3 6-6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}
