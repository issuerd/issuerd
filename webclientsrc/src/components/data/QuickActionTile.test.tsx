// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Plus } from 'lucide-react'
import QuickActionTile from './QuickActionTile'

describe('QuickActionTile', () => {
  it('renders label and icon', () => {
    render(<QuickActionTile label="Add" icon={Plus} />)
    expect(screen.getByText('Add')).toBeInTheDocument()
  })

  it('calls onClick when clicked', async () => {
    const user = userEvent.setup()
    const onClick = vi.fn()
    render(<QuickActionTile label="Add" icon={Plus} onClick={onClick} />)
    await user.click(screen.getByText('Add'))
    expect(onClick).toHaveBeenCalled()
  })

  it('renders as a link when href is provided', () => {
    render(<QuickActionTile label="Add" icon={Plus} href="/admin/users" />)
    expect(document.querySelector('a')).toHaveAttribute('href', '/admin/users')
  })
})
