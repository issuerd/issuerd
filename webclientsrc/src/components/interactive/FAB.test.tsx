// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import FAB from './FAB'

describe('FAB', () => {
  it('renders and calls onClick', () => {
    const onClick = vi.fn()
    render(<FAB label="Add" onClick={onClick} />)
    const btn = screen.getByRole('button')
    fireEvent.click(btn)
    expect(onClick).toHaveBeenCalled()
  })

  it('shows tooltip on hover', () => {
    render(<FAB label="Add New" onClick={() => {}} />)
    fireEvent.mouseEnter(screen.getByRole('button'))
    expect(screen.getByText('Add New')).toBeInTheDocument()
  })

  it('hides tooltip on mouse leave', () => {
    render(<FAB label="Add New" onClick={() => {}} />)
    const btn = screen.getByRole('button')
    fireEvent.mouseEnter(btn)
    expect(screen.getByText('Add New')).toBeInTheDocument()
    fireEvent.mouseLeave(btn)
    expect(screen.queryByText('Add New')).not.toBeInTheDocument()
  })
})
