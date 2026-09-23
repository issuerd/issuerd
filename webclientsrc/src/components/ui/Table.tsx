// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import React from 'react'
import { cn } from '@/lib/utils'

interface TableProps {
  children: React.ReactNode
  className?: string
}

export function Table({ children, className }: TableProps) {
  return (
    <div className={cn('rounded-xl border border-border overflow-hidden bg-card', className)}>
      <div className="overflow-x-auto">
        <table className="w-full caption-bottom text-sm">{children}</table>
      </div>
    </div>
  )
}

export function Thead({ children }: { children: React.ReactNode }) {
  return <thead className="[&_tr]:border-b">{children}</thead>
}

export function Tbody({ children }: { children: React.ReactNode }) {
  return <tbody className="[&_tr:last-child]:border-0">{children}</tbody>
}

export function Tr({
  children,
  onClick,
  className,
}: {
  children: React.ReactNode
  onClick?: () => void
  className?: string
}) {
  return (
    <tr
      className={cn(
        'border-b transition-colors hover:bg-muted/50',
        onClick && 'cursor-pointer',
        className
      )}
      onClick={onClick}
    >
      {children}
    </tr>
  )
}

export function Th({ children, align }: { children: React.ReactNode; align?: 'right' }) {
  return (
    <th
      className="h-10 px-4 text-left align-middle font-medium whitespace-nowrap text-foreground bg-muted/30"
      style={{ textAlign: align ?? 'left' }}
    >
      {children}
    </th>
  )
}

export function Td({ children, align, className }: { children: React.ReactNode; align?: 'right'; className?: string }) {
  return (
    <td
      className={cn('px-4 py-3 align-middle', className)}
      style={{ textAlign: align ?? 'left' }}
    >
      {children}
    </td>
  )
}
