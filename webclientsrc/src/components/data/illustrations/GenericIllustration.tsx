// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { cn } from '@/lib/utils'

interface GenericIllustrationProps {
  className?: string
}

export default function GenericIllustration({ className }: GenericIllustrationProps) {
  return (
    <svg
      viewBox="0 0 120 120"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={cn('w-24 h-24', className)}
      aria-hidden="true"
    >
      <rect
        x="28"
        y="28"
        width="64"
        height="64"
        rx="8"
        stroke="currentColor"
        strokeWidth="2"
        strokeDasharray="6 4"
      />
      <circle cx="60" cy="52" r="12" stroke="currentColor" strokeWidth="2" />
      <path
        d="M44 84c0-8.837 7.163-16 16-16s16 7.163 16 16"
        stroke="currentColor"
        strokeWidth="2"
      />
      <circle cx="92" cy="92" r="8" fill="currentColor" fillOpacity="0.12" />
      <path d="M88 92h8M92 88v8" stroke="currentColor" strokeWidth="2" />
    </svg>
  )
}
