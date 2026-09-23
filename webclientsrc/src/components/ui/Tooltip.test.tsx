// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import Tooltip from './Tooltip'

describe('Tooltip', () => {
  it('renders children', () => {
    render(
      <Tooltip content="Hint">
        <button>Hover me</button>
      </Tooltip>
    )
    expect(screen.getByText('Hover me')).toBeInTheDocument()
  })

  it('does not show tooltip when disabled', async () => {
    render(
      <Tooltip content="Hint" disabled>
        <button>Hover me</button>
      </Tooltip>
    )
    await userEvent.hover(screen.getByText('Hover me'))
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
  })

  it('shows tooltip on hover', async () => {
    render(
      <Tooltip content="Hint">
        <button>Hover me</button>
      </Tooltip>
    )
    await userEvent.hover(screen.getByText('Hover me'))
    await waitFor(() => {
      expect(screen.getByRole('tooltip')).toHaveTextContent('Hint')
    })
  })

  it('hides tooltip on unhover', async () => {
    render(
      <Tooltip content="Hint">
        <button>Hover me</button>
      </Tooltip>
    )
    const btn = screen.getByText('Hover me')
    await userEvent.hover(btn)
    await waitFor(() => {
      expect(screen.getByRole('tooltip')).toBeInTheDocument()
    })
    await userEvent.unhover(btn)
    await waitFor(() => {
      expect(btn).not.toHaveAttribute('aria-describedby')
    })
  })

  it('supports different placements', async () => {
    const { rerender } = render(
      <Tooltip content="Hint" placement="bottom">
        <button>Hover</button>
      </Tooltip>
    )
    await userEvent.hover(screen.getByText('Hover'))
    await waitFor(() => {
      expect(screen.getByRole('tooltip')).toBeInTheDocument()
    })
    rerender(
      <Tooltip content="Hint" placement="left">
        <button>Hover</button>
      </Tooltip>
    )
    await waitFor(() => {
      expect(screen.getByRole('tooltip')).toBeInTheDocument()
    })
  })
})
