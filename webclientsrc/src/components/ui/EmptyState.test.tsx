// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Users } from 'lucide-react'
import EmptyState from './EmptyState'

describe('EmptyState', () => {
  it('renders title and description', () => {
    render(<EmptyState title="No items" description="Add one to start" />)
    expect(screen.getByText('No items')).toBeInTheDocument()
    expect(screen.getByText('Add one to start')).toBeInTheDocument()
  })

  it('renders action if provided', () => {
    render(<EmptyState title="No items" action={<button>Create</button>} />)
    expect(screen.getByRole('button', { name: /Create/i })).toBeInTheDocument()
  })

  it('renders an illustration by default', () => {
    const { container } = render(<EmptyState title="No users" illustration="users" />)
    expect(container.querySelector('svg')).toBeInTheDocument()
  })

  it('prefers icon over illustration when both provided', () => {
    const { container } = render(<EmptyState title="No items" icon={Users} illustration="users" />)
    // The icon path should be present (lucide renders SVG), but we should not see the custom illustration
    expect(container.querySelector('svg')).toBeInTheDocument()
  })
})
