// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Users } from 'lucide-react'
import StatCard from './StatCard'

describe('StatCard', () => {
  it('renders title, value, and trend label', () => {
    render(<StatCard title="Users" value={42} trend="up" trendLabel="+5%" icon={Users} />)
    expect(screen.getByText('Users')).toBeInTheDocument()
    expect(screen.getByText('42')).toBeInTheDocument()
    expect(screen.getByText('+5%')).toBeInTheDocument()
  })

  it('shows loading skeleton', () => {
    render(<StatCard title="Users" value={0} icon={Users} loading />)
    expect(screen.queryByText('0')).not.toBeInTheDocument()
  })

  it('renders as a link when href is provided', () => {
    render(<StatCard title="Users" value={42} icon={Users} href="/admin/users" />)
    expect(document.querySelector('a')).toHaveAttribute('href', '/admin/users')
  })
})
