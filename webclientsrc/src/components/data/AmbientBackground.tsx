// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { cn } from '@/lib/utils'

interface AmbientBackgroundProps {
  className?: string
}

export default function AmbientBackground({ className }: AmbientBackgroundProps) {
  return (
    <div
      className={cn('fixed inset-0 -z-10 overflow-hidden pointer-events-none', className)}
      aria-hidden="true"
    >
      <div
        className="absolute -top-[20%] -left-[10%] w-[60%] h-[60%] rounded-full opacity-[0.03] animate-float"
        style={{
          background: 'radial-gradient(circle, rgba(0,229,255,0.6) 0%, transparent 70%)',
        }}
      />
      <div
        className="absolute top-[40%] -right-[10%] w-[50%] h-[50%] rounded-full opacity-[0.02] animate-float"
        style={{
          background: 'radial-gradient(circle, rgba(124,77,255,0.6) 0%, transparent 70%)',
          animationDelay: '-3s',
        }}
      />
      <div
        className="absolute -bottom-[10%] left-[20%] w-[40%] h-[40%] rounded-full opacity-[0.02] animate-float"
        style={{
          background: 'radial-gradient(circle, rgba(0,230,118,0.5) 0%, transparent 70%)',
          animationDelay: '-5s',
        }}
      />
    </div>
  )
}
