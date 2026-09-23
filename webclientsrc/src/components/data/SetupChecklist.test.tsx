// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import SetupChecklist from './SetupChecklist'
import { Globe } from 'lucide-react'

const items = [
  { id: '1', label: 'Step 1', description: 'Desc 1', completed: true, icon: Globe, action: vi.fn() },
  { id: '2', label: 'Step 2', description: 'Desc 2', completed: false, icon: Globe, action: vi.fn() },
]

describe('SetupChecklist', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('renders header and items', () => {
    render(<SetupChecklist realm="master" items={items} />)
    expect(screen.getByText('Realm Setup')).toBeInTheDocument()
    expect(screen.getByText('Step 1')).toBeInTheDocument()
    expect(screen.getByText('Step 2')).toBeInTheDocument()
  })

  it('toggles expand/collapse', () => {
    render(<SetupChecklist realm="master" items={items} />)
    const toggle = screen.getByLabelText('Collapse')
    fireEvent.click(toggle)
    expect(screen.getByLabelText('Expand')).toBeInTheDocument()
  })

  it('dismisses and persists', () => {
    render(<SetupChecklist realm="master" items={items} />)
    fireEvent.click(screen.getByLabelText('Dismiss'))
    expect(screen.queryByText('Realm Setup')).not.toBeInTheDocument()
    expect(localStorage.getItem('issuerd-setup-checklist-dismissed-master')).toBe('true')
  })

  it('does not render when previously dismissed', () => {
    localStorage.setItem('issuerd-setup-checklist-dismissed-master', 'true')
    const { container } = render(<SetupChecklist realm="master" items={items} />)
    expect(container.firstChild).toBeNull()
  })

  it('calls item action on click', () => {
    render(<SetupChecklist realm="master" items={items} />)
    fireEvent.click(screen.getByText('Step 2'))
    expect(items[1].action).toHaveBeenCalled()
  })
})
