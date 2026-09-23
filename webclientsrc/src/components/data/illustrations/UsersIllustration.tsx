// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { cn } from '@/lib/utils'

interface UsersIllustrationProps {
  className?: string
}

export default function UsersIllustration({ className }: UsersIllustrationProps) {
  return (
    <svg
      viewBox="0 0 120 120"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={cn('w-24 h-24', className)}
      aria-hidden="true"
    >
      <circle cx="60" cy="46" r="18" stroke="currentColor" strokeWidth="2" strokeDasharray="4 3" />
      <path
        d="M36 88c0-13.255 10.745-24 24-24s24 10.745 24 24"
        stroke="currentColor"
        strokeWidth="2"
      />
      <circle cx="88" cy="38" r="12" stroke="currentColor" strokeWidth="2" />
      <path d="M76 72c0-8.837 5.373-16 12-16s12 7.163 12 16" stroke="currentColor" strokeWidth="2" />
      <circle cx="94" cy="88" r="8" fill="currentColor" fillOpacity="0.12" />
      <path d="M90 88h8M94 84v8" stroke="currentColor" strokeWidth="2" />
    </svg>
  )
}
