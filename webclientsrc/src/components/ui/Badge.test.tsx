// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import Badge from './Badge'

describe('Badge', () => {
  it('renders children', () => {
    render(<Badge>Test</Badge>)
    expect(screen.getByText('Test')).toBeInTheDocument()
  })

  it('applies variant classes', () => {
    const { rerender } = render(<Badge variant="success">S</Badge>)
    expect(screen.getByText('S')).toHaveClass('bg-em-500/10')

    rerender(<Badge variant="danger">D</Badge>)
    expect(screen.getByText('D')).toHaveClass('bg-red-500/10')

    rerender(<Badge variant="warning">W</Badge>)
    expect(screen.getByText('W')).toHaveClass('bg-amber-500/10')

    rerender(<Badge variant="info">I</Badge>)
    expect(screen.getByText('I')).toHaveClass('bg-blue-500/10')
  })

  it('applies custom className', () => {
    render(<Badge className="extra">Test</Badge>)
    expect(screen.getByText('Test')).toHaveClass('extra')
  })
})
