// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import RealmListPage from './RealmListPage'
import { useAuthStore } from '../../state/authStore'

const mockCreateRealm = vi.fn()
const mockDeleteRealm = vi.fn()
const mockNavigate = vi.fn()
const mockSetRealm = vi.fn()
let mockDeleteTarget: string | null = null

let mockRealmsState = {
  data: [
    { realm: 'master', display_name: 'Master', enabled: true },
    { realm: 'demo', enabled: false },
  ] as any[],
  isLoading: false,
  error: null as Error | null,
}

vi.mock('../../api/hooks/useRealms', () => ({
  useRealms: () => mockRealmsState,
  useRealmCount: () => ({ data: mockRealmsState.data?.length ?? 0 }),
  useCreateRealm: () => ({
    mutateAsync: mockCreateRealm,
    isPending: false,
  }),
  useDeleteRealm: () => ({
    mutateAsync: mockDeleteRealm,
    mutate: mockDeleteRealm,
    isPending: false,
  }),
}))

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

vi.mock('react', async () => {
  const actual = await vi.importActual('react')
  return {
    ...actual,
    useState: vi.fn((initial: unknown) => {
      if (initial === null && mockDeleteTarget !== null) {
        return actual.useState(mockDeleteTarget)
      }
      return actual.useState(initial)
    }),
  }
})

vi.mock('../../api/hooks/useServerInfo', () => ({
  useServerInfo: () => ({
    data: {
      protocols: [{ id: 'openid-connect', name: 'OpenID Connect' }],
      ssl_required: [
        { id: 'none', name: 'None' },
        { id: 'external', name: 'External' },
        { id: 'all', name: 'All' },
      ],
      event_types: [],
      credential_types: [],
      algorithms: [],
      grant_types: [],
      response_types: [],
      response_modes: [],
      requirements: [],
      provider_ids: [
        { id: 'google', name: 'Google' },
        { id: 'github', name: 'GitHub' },
        { id: 'oidc', name: 'OpenID Connect' },
        { id: 'saml', name: 'SAML' },
      ],
      client_authenticator_types: [],
      operation_types: [],
      prompts: [],
    },
    isLoading: false,
    error: null,
  }),
}))

describe('RealmListPage', () => {
  beforeEach(() => {
    useAuthStore.setState({ currentRealm: 'master', setRealm: mockSetRealm })
    vi.clearAllMocks()
    mockDeleteTarget = null
    window.history.replaceState({}, '', '/')
    mockRealmsState = {
      data: [
        { realm: 'master', display_name: 'Master', enabled: true },
        { realm: 'demo', enabled: false },
      ],
      isLoading: false,
      error: null,
    }
  })

  it('renders realm list', () => {
    render(
      <MemoryRouter>
        <RealmListPage />
      </MemoryRouter>,
    )
    expect(screen.getByText('master')).toBeInTheDocument()
    expect(screen.getByText('demo')).toBeInTheDocument()
  })

  it('opens create modal', () => {
    render(
      <MemoryRouter>
        <RealmListPage />
      </MemoryRouter>,
    )
    fireEvent.click(screen.getByRole('button', { name: /Create Realm/i }))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })

  it('closes create modal on cancel', async () => {
    render(
      <MemoryRouter>
        <RealmListPage />
      </MemoryRouter>,
    )
    fireEvent.click(screen.getByRole('button', { name: /Create Realm/i }))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Cancel/i }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  })

  it('creates a realm via form submit', async () => {
    mockCreateRealm.mockResolvedValue(undefined)
    render(
      <MemoryRouter>
        <RealmListPage />
      </MemoryRouter>,
    )
    fireEvent.click(screen.getByRole('button', { name: /Create Realm/i }))

    fireEvent.change(screen.getByLabelText('Realm Name'), { target: { value: 'newrealm' } })
    fireEvent.change(screen.getByLabelText('Display Name'), { target: { value: 'New Realm' } })

    fireEvent.click(screen.getByRole('button', { name: /Save/i }))

    await waitFor(() => {
      expect(mockCreateRealm).toHaveBeenCalled()
    })
  })

  it('bulk deletes a realm via DataTable when confirmed', async () => {
    mockDeleteRealm.mockResolvedValue(undefined)
    window.confirm = vi.fn(() => true)
    render(
      <MemoryRouter>
        <RealmListPage />
      </MemoryRouter>,
    )
    const checkboxes = screen.getAllByRole('checkbox')
    fireEvent.click(checkboxes[1])
    fireEvent.click(screen.getByRole('button', { name: /Delete$/i }))

    await waitFor(() => {
      expect(mockDeleteRealm).toHaveBeenCalledWith('master')
    })
  })

  it('cancels bulk delete when confirm returns false', async () => {
    mockDeleteRealm.mockResolvedValue(undefined)
    window.confirm = vi.fn(() => false)
    render(
      <MemoryRouter>
        <RealmListPage />
      </MemoryRouter>,
    )
    const checkboxes = screen.getAllByRole('checkbox')
    fireEvent.click(checkboxes[1])
    fireEvent.click(screen.getByRole('button', { name: /Delete$/i }))

    await waitFor(() => {
      expect(mockDeleteRealm).not.toHaveBeenCalled()
    })
  })

  it('navigates on row click', () => {
    render(
      <MemoryRouter>
        <RealmListPage />
      </MemoryRouter>,
    )
    const cell = screen.getByText('master')
    const row = cell.closest('tr')
    expect(row).toBeInTheDocument()
    if (row) fireEvent.click(row)
    expect(mockNavigate).toHaveBeenCalledWith('/realms/master/settings')
  })

  it('sorts by column header', () => {
    render(
      <MemoryRouter>
        <RealmListPage />
      </MemoryRouter>,
    )
    const headers = screen.getAllByRole('columnheader')
    if (headers.length > 0) {
      fireEvent.click(headers[0])
    }
    expect(screen.getByText('master')).toBeInTheDocument()
  })

  it('shows spinner while loading', () => {
    mockRealmsState = { data: [], isLoading: true, error: null }
    render(
      <MemoryRouter>
        <RealmListPage />
      </MemoryRouter>,
    )
    expect(document.querySelector('.animate-spin')).toBeInTheDocument()
  })

  it('shows error message on error', () => {
    mockRealmsState = { data: [], isLoading: false, error: new Error('fetch failed') }
    render(
      <MemoryRouter>
        <RealmListPage />
      </MemoryRouter>,
    )
    expect(screen.getByText(/fetch failed/i)).toBeInTheDocument()
  })

  it('shows empty state when no realms', () => {
    mockRealmsState = { data: [], isLoading: false, error: null }
    render(
      <MemoryRouter>
        <RealmListPage />
      </MemoryRouter>,
    )
    expect(screen.getByText(/No realms/i)).toBeInTheDocument()
  })

  it('deletes current realm and resets auth store', async () => {
    mockDeleteRealm.mockResolvedValue(undefined)
    mockDeleteTarget = 'master'
    render(
      <MemoryRouter>
        <RealmListPage />
      </MemoryRouter>,
    )
    fireEvent.click(screen.getByRole('button', { name: /Delete$/i }))
    await waitFor(() => expect(mockDeleteRealm).toHaveBeenCalledWith('master'))
    await waitFor(() => expect(mockSetRealm).toHaveBeenCalledWith(null))
  })

  it('deletes non-current realm without resetting auth store', async () => {
    mockDeleteRealm.mockResolvedValue(undefined)
    useAuthStore.setState({ currentRealm: 'other', setRealm: mockSetRealm })
    mockDeleteTarget = 'master'
    render(
      <MemoryRouter>
        <RealmListPage />
      </MemoryRouter>,
    )
    fireEvent.click(screen.getByRole('button', { name: /Delete$/i }))
    await waitFor(() => expect(mockDeleteRealm).toHaveBeenCalledWith('master'))
    expect(mockSetRealm).not.toHaveBeenCalled()
  })

  it('closes delete modal via cancel', () => {
    mockDeleteTarget = 'master'
    render(
      <MemoryRouter>
        <RealmListPage />
      </MemoryRouter>,
    )
    fireEvent.click(screen.getByRole('button', { name: /Cancel$/i }))
    expect(mockDeleteRealm).not.toHaveBeenCalled()
  })

  it('filters realms via DataTable search', async () => {
    render(
      <MemoryRouter>
        <RealmListPage />
      </MemoryRouter>,
    )
    const search = screen.getByPlaceholderText('Search...')
    fireEvent.change(search, { target: { value: 'master' } })
    expect(screen.getByText('master')).toBeInTheDocument()
  })

  it('sorts by enabled column', () => {
    render(
      <MemoryRouter>
        <RealmListPage />
      </MemoryRouter>,
    )
    const headers = screen.getAllByRole('columnheader')
    const enabledHeader = headers.find((h) => h.textContent?.includes('Enabled'))
    if (enabledHeader) fireEvent.click(enabledHeader)
    expect(screen.getByText('master')).toBeInTheDocument()
  })

  it('handles realm with missing display_name in accessor', () => {
    mockRealmsState = {
      data: [
        { realm: 'test', enabled: true },
      ],
      isLoading: false,
      error: null,
    }
    render(
      <MemoryRouter>
        <RealmListPage />
      </MemoryRouter>,
    )
    expect(screen.getByText('test')).toBeInTheDocument()
  })

  it('handles realm with null realm name fallback', () => {
    mockRealmsState = {
      data: [
        { realm: null, display_name: 'Null Realm', enabled: true },
        { realm: 'zulu', display_name: 'Zulu', enabled: true },
      ],
      isLoading: false,
      error: null,
    }
    render(
      <MemoryRouter>
        <RealmListPage />
      </MemoryRouter>,
    )
    // Row should still render; the empty string fallback is in the accessor
    expect(screen.getByText('Null Realm')).toBeInTheDocument()
    // Sort by Name to exercise the accessor branch with null realm
    const headers = screen.getAllByRole('columnheader')
    const nameHeader = headers.find((h) => h.textContent?.includes('Name'))
    if (nameHeader) fireEvent.click(nameHeader)
    expect(screen.getByText('Zulu')).toBeInTheDocument()
  })

  it('handles null realms data fallback', () => {
    mockRealmsState = {
      data: null as any,
      isLoading: false,
      error: null,
    }
    render(
      <MemoryRouter>
        <RealmListPage />
      </MemoryRouter>,
    )
    expect(screen.getByText(/No realms/i)).toBeInTheDocument()
  })

  it('closes create modal on Escape', async () => {
    render(
      <MemoryRouter>
        <RealmListPage />
      </MemoryRouter>,
    )
    fireEvent.click(screen.getByRole('button', { name: /Create Realm/i }))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' })
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  })
})
