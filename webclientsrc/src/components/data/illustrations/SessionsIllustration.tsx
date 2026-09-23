// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { cn } from '@/lib/utils'

interface SessionsIllustrationProps {
  className?: string
}

export default function SessionsIllustration({ className }: SessionsIllustrationProps) {
  return (
    <svg
      viewBox="0 0 120 120"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={cn('w-24 h-24', className)}
      aria-hidden="true"
    >
      <rect x="20" y="28" width="80" height="56" rx="6" stroke="currentColor" strokeWidth="2" />
      <path d="M20 44h80" stroke="currentColor" strokeWidth="2" />
      <circle cx="32" cy="36" r="2" fill="currentColor" />
      <circle cx="40" cy="36" r="2" fill="currentColor" />
      <circle cx="48" cy="36" r="2" fill="currentColor" />
      <rect x="36" y="56" width="48" height="4" rx="1" fill="currentColor" fillOpacity="0.12" />
      <rect x="36" y="66" width="32" height="4" rx="1" fill="currentColor" fillOpacity="0.12" />
      <path d="M48 96h24" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      <path d="M54 104h12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      <path d="M60 84v8" stroke="currentColor" strokeWidth="2" />
      <circle cx="76" cy="74" r="6" fill="currentColor" fillOpacity="0.12" />
      <path d="M73 74l2 2 4-4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}
