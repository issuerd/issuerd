// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import ToastContainer from './ToastContainer'

const mockUseToastStore = vi.fn()
vi.mock('@/stores/toastStore', () => ({
  useToastStore: (...args: unknown[]) => mockUseToastStore(...args),
}))

describe('ToastContainer', () => {
  it('renders toasts', () => {
    mockUseToastStore.mockImplementation((selector: (s: { toasts: Array<{ id: string; title: string; type: string; duration: number }> }) => unknown) =>
      selector({
        toasts: [
          { id: '1', title: 'A', type: 'info', duration: 4000 },
          { id: '2', title: 'B', type: 'error', duration: 4000 },
        ],
      })
    )
    render(<ToastContainer />)
    expect(screen.getByText('A')).toBeInTheDocument()
    expect(screen.getByText('B')).toBeInTheDocument()
  })

  it('renders nothing when no toasts', () => {
    mockUseToastStore.mockImplementation((selector: (s: { toasts: [] }) => unknown) =>
      selector({ toasts: [] })
    )
    const { container } = render(<ToastContainer />)
    expect(container.firstChild).toBeNull()
  })
})
