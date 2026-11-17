// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import AdminEventFilterBar from './AdminEventFilterBar'

vi.mock('../../api/hooks/useServerInfo', () => ({
  useServerInfo: () => ({
    data: {
      operation_types: [
        { id: 'CREATE', name: 'Create', description: 'Resource created' },
        { id: 'DELETE', name: 'Delete', description: 'Resource deleted' },
      ],
      resource_types: [
        { id: 'USER', name: 'User', description: 'User resource' },
        { id: 'CLIENT', name: 'Client', description: 'Client resource' },
      ],
    },
    isLoading: false,
  }),
}))

describe('AdminEventFilterBar', () => {
  it('emits operation, resource, and normalized date filters and applies them', () => {
    const onChange = vi.fn()
    const onApply = vi.fn()
    const filters = { max: 25 }
    const { container } = render(
      <AdminEventFilterBar filters={filters} onChange={onChange} onApply={onApply} />,
    )

    const selects = screen.getAllByRole('combobox')
    fireEvent.change(selects[0], { target: { value: 'CREATE' } })
    expect(onChange).toHaveBeenLastCalledWith({ ...filters, operation_type: 'CREATE' })
    fireEvent.change(selects[0], { target: { value: '' } })
    expect(onChange).toHaveBeenLastCalledWith({ ...filters, operation_type: undefined })
    fireEvent.change(selects[1], { target: { value: 'USER' } })
    expect(onChange).toHaveBeenLastCalledWith({ ...filters, resource_type: 'USER' })
    fireEvent.change(selects[1], { target: { value: '' } })
    expect(onChange).toHaveBeenLastCalledWith({ ...filters, resource_type: undefined })

    const dates = container.querySelectorAll('input[type="date"]')
    fireEvent.change(dates[0], { target: { value: '2026-02-03' } })
    expect(onChange).toHaveBeenLastCalledWith({
      ...filters,
      date_from: '2026-02-03T00:00:00.000Z',
    })
    fireEvent.change(dates[1], { target: { value: '2026-02-04' } })
    expect(onChange).toHaveBeenLastCalledWith({
      ...filters,
      date_to: '2026-02-04T23:59:59.999Z',
    })

    fireEvent.click(screen.getByRole('button', { name: 'Apply' }))
    expect(onApply).toHaveBeenCalledOnce()
  })

  it('shows selected operation and resource descriptions', () => {
    render(
      <AdminEventFilterBar
        filters={{ operation_type: 'CREATE', resource_type: 'USER' }}
        onChange={vi.fn()}
        onApply={vi.fn()}
      />,
    )

    expect(screen.getByText('Resource created')).toBeInTheDocument()
    expect(screen.getByText('User resource')).toBeInTheDocument()
  })
})
