// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi } from 'vitest'
import { screen, fireEvent, waitFor } from '@testing-library/react'
import SessionListPage from './SessionListPage'
import { renderWithProviders } from '../../test/utils'

vi.mock('../../state/authStore', () => ({
  useAuthStore: (selector: any) => selector({ currentRealm: 'master' }),
}))

const sessions = [
  {
    id: 's1',
    username: 'alice',
    user_id: 'u1',
    ip_address: '127.0.0.1',
    started: 1700000000,
    last_access: 1700000100,
    offline: false,
    clients: {},
  },
  {
    id: 's2',
    username: 'bob',
    user_id: 'u2',
    ip_address: '127.0.0.2',
    started: 1700000000,
    last_access: 1700000100,
    offline: true,
    clients: {},
  },
]

vi.mock('../../api/hooks/useSessions', () => ({
  useSessions: () => ({ data: sessions, isLoading: false, error: null }),
  useSessionCount: () => ({ data: 2 }),
  useDeleteSession: () => ({ mutate: vi.fn() }),
}))

describe('SessionListPage', () => {
  it('marks offline sessions with a badge and online ones without', async () => {
    renderWithProviders(<SessionListPage />)

    expect(await screen.findByText('alice')).toBeInTheDocument()
    expect(screen.getByText('bob')).toBeInTheDocument()
    expect(screen.getByText('Offline')).toBeInTheDocument()
    expect(screen.getByText('Online')).toBeInTheDocument()
  })

  it('shows the offline explanation in the detail drawer', async () => {
    renderWithProviders(<SessionListPage />)

    fireEvent.click(await screen.findByText('bob'))
    await waitFor(() => {
      expect(
        screen.getByText(/Backs an offline_access refresh token/i),
      ).toBeInTheDocument()
    })
  })
})
