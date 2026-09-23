// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import ConsentsPage from './ConsentsPage'

const mockListConsents = vi.fn()
const mockDeleteConsent = vi.fn()

vi.mock('@generated', () => ({
  accountListConsents: (...args: unknown[]) => mockListConsents(...args),
  accountDeleteConsent: (...args: unknown[]) => mockDeleteConsent(...args),
}))

const consent = {
  client_id: 'web-app',
  granted_scopes: ['openid', 'profile'],
  created_at: '2026-01-01T10:00:00Z',
  last_updated_at: '2026-02-01T12:00:00Z',
}

function resolved(data: unknown) {
  return { data, error: undefined, response: { status: 200 } }
}

describe('ConsentsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('shows an empty state when there are no consents', async () => {
    mockListConsents.mockResolvedValue(resolved([]))
    render(<ConsentsPage />)
    expect(
      await screen.findByText('You have not granted access to any applications yet.')
    ).toBeInTheDocument()
  })

  it('renders a row per consent with scopes as chips', async () => {
    mockListConsents.mockResolvedValue(resolved([consent]))
    render(<ConsentsPage />)
    expect(await screen.findByText('web-app')).toBeInTheDocument()
    expect(screen.getByText('openid')).toBeInTheDocument()
    expect(screen.getByText('profile')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Revoke' })).toBeInTheDocument()
  })

  it('revokes a consent and reloads the list', async () => {
    mockListConsents
      .mockResolvedValueOnce(resolved([consent]))
      .mockResolvedValueOnce(resolved([]))
    mockDeleteConsent.mockResolvedValue(resolved(undefined))
    render(<ConsentsPage />)

    fireEvent.click(await screen.findByRole('button', { name: 'Revoke' }))

    await waitFor(() =>
      expect(mockDeleteConsent).toHaveBeenCalledWith({
        path: { realm: 'master', client_id: 'web-app' },
      })
    )
    expect(
      await screen.findByText('You have not granted access to any applications yet.')
    ).toBeInTheDocument()
    expect(mockListConsents).toHaveBeenCalledTimes(2)
  })
})
