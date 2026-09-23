// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import KeysPage from './KeysPage'

const mockRotate = vi.fn()
const mockDisable = vi.fn()
const mockUpdateRealm = vi.fn()

let mockKeysState: {
  data: {
    active: Record<string, string>
    passive: Array<{ kid: string; algorithm: string; provider_id: string; status: string }>
  } | null
  isLoading: boolean
  error: Error | null
}

vi.mock('../../state/authStore', () => ({
  useAuthStore: (selector: any) => selector({ currentRealm: 'master' }),
}))

vi.mock('../../api/hooks/useKeys', () => ({
  useKeys: () => mockKeysState,
  useRotateKeys: () => ({ mutate: mockRotate, isPending: false }),
  useDisableKey: () => ({ mutate: mockDisable, isPending: false }),
}))

vi.mock('../../api/hooks/useRealms', () => ({
  useRealm: () => ({
    data: {
      realm: 'master',
      display_name: 'Master',
      attributes: { default_signature_algorithm: 'ES256' },
    },
    isLoading: false,
    error: null,
  }),
  useUpdateRealm: () => ({ mutate: mockUpdateRealm, isPending: false }),
}))

vi.mock('../../api/hooks/useServerInfo', () => ({
  useServerInfo: () => ({
    data: {
      algorithms: [
        { id: 'RS256', name: 'RS256', description: 'RSA with SHA-256' },
        { id: 'ES256', name: 'ES256', description: 'ECDSA with SHA-256' },
        { id: 'ES512', name: 'ES512', description: 'ECDSA with SHA-512' },
      ],
    },
    isLoading: false,
    error: null,
  }),
}))

function renderPage() {
  return render(
    <MemoryRouter>
      <KeysPage />
    </MemoryRouter>
  )
}

describe('KeysPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockKeysState = {
      data: {
        active: { RS256: 'kid-active' },
        passive: [
          { kid: 'kid-old', algorithm: 'RS256', provider_id: 'rsa', status: 'PASSIVE' },
        ],
      },
      isLoading: false,
      error: null,
    }
  })

  it('renders the key metadata table', () => {
    renderPage()
    expect(screen.getByText('kid-active')).toBeInTheDocument()
    expect(screen.getByText('kid-old')).toBeInTheDocument()
    expect(screen.getByText('active')).toBeInTheDocument()
    expect(screen.getByText('Passive')).toBeInTheDocument()
  })

  it('rotates keys from the header button using the realm algorithm', () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: /Rotate Keys/i }))
    expect(mockRotate).toHaveBeenCalledWith({ realm: 'master', algorithm: 'ES256' })
  })

  it('rotates the algorithm selected in the rotation picker', () => {
    renderPage()
    fireEvent.change(screen.getByLabelText('Rotation algorithm'), { target: { value: 'ES512' } })
    fireEvent.click(screen.getByRole('button', { name: /Rotate Keys/i }))
    expect(mockRotate).toHaveBeenCalledWith({ realm: 'master', algorithm: 'ES512' })
  })

  it('shows the realm signing algorithm selector sourced from serverinfo', () => {
    renderPage()
    const select = screen.getByLabelText('Realm signing algorithm') as HTMLSelectElement
    expect(select.value).toBe('ES256')
    const options = Array.from(select.options).map((o) => o.value)
    expect(options).toEqual(['RS256', 'ES256', 'ES512'])
    // Enum descriptions surface as native tooltips.
    expect(select.options[0].title).toBe('RSA with SHA-256')
  })

  it('persists the realm signing algorithm through the realm update', () => {
    renderPage()
    fireEvent.change(screen.getByLabelText('Realm signing algorithm'), {
      target: { value: 'RS256' },
    })
    expect(mockUpdateRealm).toHaveBeenCalledWith({
      realm: 'master',
      body: {
        realm: 'master',
        display_name: 'Master',
        attributes: { default_signature_algorithm: 'RS256' },
      },
    })
  })

  it('disables an active key from its row action', () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Disable' }))
    expect(mockDisable).toHaveBeenCalledWith({ realm: 'master', kid: 'kid-active' })
  })

  it('does not offer Disable for passive keys', () => {
    renderPage()
    expect(screen.getAllByRole('button', { name: 'Disable' })).toHaveLength(1)
  })

  it('shows spinner while loading', () => {
    mockKeysState = { data: null, isLoading: true, error: null }
    renderPage()
    expect(document.querySelector('.animate-spin')).toBeInTheDocument()
  })

  it('shows error message on error', () => {
    mockKeysState = { data: null, isLoading: false, error: new Error('keys failed') }
    renderPage()
    expect(screen.getByText(/keys failed/i)).toBeInTheDocument()
  })
})
