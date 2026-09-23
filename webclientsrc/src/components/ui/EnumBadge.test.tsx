// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import EnumBadge from './EnumBadge'
import type { EnumValueRepresentation } from '@generated'

const enumList: EnumValueRepresentation[] = [
  { id: 'login', name: 'Login', description: 'Successful user login' },
  { id: 'logout', name: 'Logout', description: null },
]

describe('EnumBadge', () => {
  it('renders the enum name', () => {
    render(<EnumBadge enumList={enumList} value="login" />)
    expect(screen.getByText('Login')).toBeInTheDocument()
  })

  it('falls back to value when enum is unknown', () => {
    render(<EnumBadge enumList={enumList} value="register" />)
    expect(screen.getByText('register')).toBeInTheDocument()
  })

  it('uses explicit fallback when value is missing', () => {
    render(<EnumBadge enumList={enumList} value={null} fallback="Unknown" />)
    expect(screen.getByText('Unknown')).toBeInTheDocument()
  })

  it('shows description tooltip on hover', async () => {
    const user = userEvent.setup()
    render(<EnumBadge enumList={enumList} value="login" />)
    const badge = screen.getByText('Login')
    await user.hover(badge)
    expect(await screen.findByRole('tooltip')).toHaveTextContent('Successful user login')
  })

  it('does not wrap in tooltip when description is missing', async () => {
    const user = userEvent.setup()
    render(<EnumBadge enumList={enumList} value="logout" />)
    const badge = screen.getByText('Logout')
    await user.hover(badge)
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
  })
})
