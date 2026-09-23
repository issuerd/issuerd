// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { Skeleton, SkeletonText, SkeletonCard, SkeletonTable, SkeletonStat } from './Skeleton'

describe('Skeleton', () => {
  it('Skeleton renders with shimmer class', () => {
    const { container } = render(<Skeleton className="h-4 w-20" />)
    expect(container.querySelector('.animate-pulse')).toBeInTheDocument()
  })

  it('SkeletonText renders multiple lines', () => {
    render(<SkeletonText lines={3} />)
    const lines = screen.getAllByRole('generic', { hidden: true })
    expect(lines.length).toBeGreaterThanOrEqual(3)
  })

  it('SkeletonCard renders card structure', () => {
    const { container } = render(<SkeletonCard />)
    expect(container.querySelector('.bg-card')).toBeInTheDocument()
  })

  it('SkeletonTable renders rows and columns', () => {
    render(<SkeletonTable rows={2} columns={3} />)
    const cells = screen.getAllByRole('generic', { hidden: true })
    expect(cells.length).toBeGreaterThan(0)
  })

  it('SkeletonStat renders stat structure', () => {
    const { container } = render(<SkeletonStat />)
    expect(container.querySelector('.bg-card')).toBeInTheDocument()
  })
})
