// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import RealmPicker from './RealmPicker'
import { useAuthStore } from '../state/authStore'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

const mockNavigate = vi.fn()
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom')
  return { ...actual, useNavigate: () => mockNavigate }
})

let mockRealmsData: any = [
  { realm: 'master', display_name: 'Master', enabled: true },
  { realm: 'demo', display_name: 'Demo', enabled: false },
]
let mockRealmsLoading = false
let mockRealmsError: any = null

vi.mock('../api/hooks/useRealms', () => ({
  useRealms: () => ({
    data: mockRealmsData,
    isLoading: mockRealmsLoading,
    error: mockRealmsError,
  }),
}))

function wrapper({ children }: { children: React.ReactNode }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return (
    <QueryClientProvider client={qc}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('RealmPicker', () => {
  beforeEach(() => {
    mockNavigate.mockReset()
    mockRealmsData = [
      { realm: 'master', display_name: 'Master', enabled: true },
      { realm: 'demo', display_name: 'Demo', enabled: false },
    ]
    mockRealmsLoading = false
    mockRealmsError = null
    useAuthStore.setState({
      tokenSet: { accessToken: 'abc', refreshToken: 'r', idToken: 'i', expiresAt: Date.now() + 300_000 },
      currentRealm: null,
    })
  })

  it('renders realms', () => {
    render(<RealmPicker />, { wrapper })
    expect(screen.getByText('master')).toBeInTheDocument()
    expect(screen.getByText('demo')).toBeInTheDocument()
  })

  it('shows spinner when loading', () => {
    mockRealmsData = undefined
    mockRealmsLoading = true
    mockRealmsError = null
    const { container } = render(<RealmPicker />, { wrapper })
    expect(container.querySelector('.animate-spin')).toBeInTheDocument()
  })

  it('shows error when request fails', () => {
    mockRealmsData = undefined
    mockRealmsLoading = false
    mockRealmsError = new Error('fail')
    render(<RealmPicker />, { wrapper })
    expect(screen.getByText('fail')).toBeInTheDocument()
  })

  it('selects realm and navigates', () => {
    render(<RealmPicker />, { wrapper })
    fireEvent.click(screen.getByText('master'))
    expect(useAuthStore.getState().currentRealm).toBe('master')
    expect(mockNavigate).toHaveBeenCalledWith('/users')
  })

  it('logs out on click', async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true })
    render(<RealmPicker />, { wrapper })
    fireEvent.click(screen.getByText('Logout'))
    // logout clears tokenSet and sets window.location
    await new Promise((r) => setTimeout(r, 10))
    expect(useAuthStore.getState().tokenSet).toBeNull()
  })
})
