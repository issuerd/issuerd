// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import CopyButton from './CopyButton'

describe('CopyButton', () => {
  beforeEach(() => {
    vi.stubGlobal('navigator', {
      clipboard: { writeText: vi.fn().mockResolvedValue(undefined) },
    })
  })

  it('copies text on click', async () => {
    render(<CopyButton text="hello" />)
    fireEvent.click(screen.getByRole('button'))
    await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalledWith('hello'))
  })

  it('renders with custom size', () => {
    render(<CopyButton text="hello" size={20} />)
    expect(screen.getByRole('button')).toBeInTheDocument()
  })

  it('shows error toast when clipboard write fails', async () => {
    const toastSpy = vi.fn()
    vi.doMock('@/stores/toastStore', () => ({ toast: toastSpy }))
    const { default: CopyButtonFresh } = await import('./CopyButton')
    vi.stubGlobal('navigator', {
      clipboard: { writeText: vi.fn().mockRejectedValue(new Error('fail')) },
    })
    render(<CopyButtonFresh text="secret" />)
    fireEvent.click(screen.getByRole('button'))
    await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalledWith('secret'))
    vi.doUnmock('@/stores/toastStore')
  })
})
