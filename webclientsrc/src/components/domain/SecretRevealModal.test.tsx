// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import SecretRevealModal from './SecretRevealModal'

describe('SecretRevealModal', () => {
  it('reveals the secret only after explicit confirmation and closes', () => {
    const onClose = vi.fn()
    render(<SecretRevealModal open onClose={onClose} secret="test-secret" />)

    expect(screen.queryByText('test-secret')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Reveal Secret' }))
    expect(screen.getByText('test-secret')).toBeInTheDocument()

    fireEvent.click(screen.getByText('Close'))
    expect(onClose).toHaveBeenCalledOnce()
  })
})
