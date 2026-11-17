// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import EventFilterBar from './EventFilterBar'

vi.mock('../../api/hooks/useServerInfo', () => ({
  useServerInfo: () => ({
    data: {
      event_types: [
        { id: 'LOGIN', name: 'Login', description: 'Successful authentication' },
        { id: 'LOGOUT', name: 'Logout', description: 'Session ended' },
      ],
    },
  }),
}))

describe('EventFilterBar', () => {
  it('emits event type and normalized date filters and applies them', () => {
    const onChange = vi.fn()
    const onApply = vi.fn()
    const filters = { max: 25 }
    const { container } = render(
      <EventFilterBar filters={filters} onChange={onChange} onApply={onApply} />,
    )

    const eventType = screen.getByRole('combobox')
    fireEvent.change(eventType, { target: { value: 'LOGIN' } })
    expect(onChange).toHaveBeenLastCalledWith({ ...filters, event_type: 'LOGIN' })
    fireEvent.change(eventType, { target: { value: '' } })
    expect(onChange).toHaveBeenLastCalledWith({ ...filters, event_type: undefined })

    const dates = container.querySelectorAll('input[type="date"]')
    fireEvent.change(dates[0], { target: { value: '2026-01-02' } })
    expect(onChange).toHaveBeenLastCalledWith({
      ...filters,
      date_from: '2026-01-02T00:00:00.000Z',
    })
    fireEvent.change(dates[1], { target: { value: '2026-01-03' } })
    expect(onChange).toHaveBeenLastCalledWith({
      ...filters,
      date_to: '2026-01-03T23:59:59.999Z',
    })

    fireEvent.click(screen.getByRole('button', { name: 'Apply' }))
    expect(onApply).toHaveBeenCalledOnce()
  })

  it('shows the selected event type description', () => {
    render(
      <EventFilterBar
        filters={{ event_type: 'LOGIN', date_from: '2026-01-02T00:00:00.000Z' }}
        onChange={vi.fn()}
        onApply={vi.fn()}
      />,
    )

    expect(screen.getByText('Successful authentication')).toBeInTheDocument()
    expect(screen.getByDisplayValue('2026-01-02')).toBeInTheDocument()
  })
})
