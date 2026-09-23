// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import Toast from './Toast'

const mockDismiss = vi.fn()
vi.mock('@/stores/toastStore', () => ({
  useToastStore: (selector: (s: { dismissToast: typeof mockDismiss }) => unknown) =>
    selector({ dismissToast: mockDismiss }),
}))

describe('Toast', () => {
  it('renders title and message', () => {
    render(<Toast id="1" title="Hello" message="World" type="info" duration={4000} />)
    expect(screen.getByText('Hello')).toBeInTheDocument()
    expect(screen.getByText('World')).toBeInTheDocument()
  })

  it('renders without message', () => {
    render(<Toast id="1" title="Hello" type="success" duration={4000} />)
    expect(screen.queryByText('World')).not.toBeInTheDocument()
  })

  it('calls dismiss on click', () => {
    render(<Toast id="1" title="Hello" type="error" duration={4000} />)
    fireEvent.click(screen.getByLabelText('Dismiss notification'))
    expect(mockDismiss).toHaveBeenCalledWith('1')
  })
})
