// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import StatusBadge from './StatusBadge'

describe('StatusBadge', () => {
  it('renders status text', () => {
    render(<StatusBadge status="Active" />)
    expect(screen.getByText('Active')).toBeInTheDocument()
  })

  it('applies active style', () => {
    const { container } = render(<StatusBadge status="active" />)
    expect(container.firstChild).toHaveClass('bg-matrix-green/10')
  })

  it('applies inactive style', () => {
    const { container } = render(<StatusBadge status="inactive" />)
    expect(container.firstChild).toHaveClass('bg-alert-red/10')
  })

  it('applies pending style', () => {
    const { container } = render(<StatusBadge status="pending" />)
    expect(container.firstChild).toHaveClass('bg-amber/10')
  })

  it('applies default style for unknown status', () => {
    const { container } = render(<StatusBadge status="unknown" />)
    expect(container.firstChild).toHaveClass('bg-white/5')
  })

  it('applies custom className', () => {
    const { container } = render(<StatusBadge status="active" className="extra" />)
    expect(container.firstChild).toHaveClass('extra')
  })
})
