// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import UserDetailPage from './UserDetailPage'

const mockAddRealmRoles = vi.fn()
const mockAddClientRoles = vi.fn()
const mockUpdateCredentialLabel = vi.fn()
const mockDeleteCredential = vi.fn()
const mockMoveCredential = vi.fn()
const mockImpersonateUser = vi.fn()
const mockExecuteActionsEmail = vi.fn()

vi.mock('../../state/authStore', () => ({
  useAuthStore: (selector: any) => selector({ currentRealm: 'master' }),
}))

vi.mock('../../api/hooks/useUsers', () => ({
  useUser: () => ({
    data: { id: 'u1', username: 'alice', enabled: true },
    isLoading: false,
    error: null,
  }),
  useUpdateUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useDeleteUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useResetPassword: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useUserSessions: () => ({ data: [], isLoading: false }),
  useUserGroups: () => ({ data: [], isLoading: false }),
  useUserRealmRoles: () => ({ data: [{ id: 'r1', name: 'admin' }], isLoading: false }),
  useAvailableUserRealmRoles: () => ({ data: [{ id: 'r2', name: 'user' }], isLoading: false }),
  useUserClientRoles: () => ({ data: [], isLoading: false }),
  useAvailableUserClientRoles: () => ({ data: [{ id: 'r4', name: 'writer' }], isLoading: false }),
  useAddUserGroup: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useRemoveUserGroup: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useAddUserRealmRoles: () => ({ mutateAsync: mockAddRealmRoles, isPending: false }),
  useRemoveUserRealmRoles: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useAddUserClientRoles: () => ({ mutateAsync: mockAddClientRoles, isPending: false }),
  useRemoveUserClientRoles: () => ({ mutateAsync: vi.fn(), isPending: false }),
}))

vi.mock('../../api/hooks/useCredentials', () => ({
  useUserCredentials: () => ({
    data: [
      {
        id: 'cred-1',
        type: 'password',
        user_label: 'Primary password',
        created_date: 1700000000000,
        priority: 1,
        temporary: false,
      },
      { id: 'cred-2', type: 'totp', user_label: null, created_date: null, priority: 2 },
    ],
    isLoading: false,
  }),
  useUpdateCredentialLabel: () => ({ mutateAsync: mockUpdateCredentialLabel, isPending: false }),
  useDeleteCredential: () => ({ mutateAsync: mockDeleteCredential, isPending: false }),
  useMoveCredential: () => ({ mutateAsync: mockMoveCredential, isPending: false }),
}))

vi.mock('../../api/hooks/useUserActions', () => ({
  useImpersonateUser: () => ({ mutateAsync: mockImpersonateUser, isPending: false }),
  useExecuteActionsEmail: () => ({ mutateAsync: mockExecuteActionsEmail, isPending: false }),
}))

vi.mock('../../api/hooks/useGroups', () => ({
  useGroups: () => ({ data: [], isLoading: false }),
}))

vi.mock('../../api/hooks/useSessions', () => ({
  useDeleteSession: () => ({ mutate: vi.fn(), isPending: false }),
}))

vi.mock('../../api/hooks/useClients', () => ({
  useClients: () => ({
    data: [{ id: 'c1', client_id: 'backend-api' }],
    isLoading: false,
  }),
}))

vi.mock('../../api/hooks/useServerInfo', () => ({
  useServerInfo: () => ({
    data: {
      credential_types: [
        { id: 'password', name: 'Password', description: 'Password credential' },
        { id: 'totp', name: 'TOTP', description: 'Time-based one-time password' },
      ],
      required_actions: [
        { id: 'UPDATE_PASSWORD', name: 'Update Password', description: 'User must update their password' },
        { id: 'VERIFY_EMAIL', name: 'Verify Email', description: 'User must verify their email address' },
      ],
    },
    isLoading: false,
  }),
}))

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/admin/users/u1']}>
        <Routes>
          <Route path="/admin/users/:id" element={<UserDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  )
}

describe('UserDetailPage role mappings', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('shows assigned and available realm roles on the Role Mappings tab', () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Role Mappings' }))
    expect(screen.getByText('admin')).toBeInTheDocument()
    expect(screen.getByText('user')).toBeInTheDocument()
  })

  it('assigns a realm role from the available list', async () => {
    mockAddRealmRoles.mockResolvedValue(undefined)
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Role Mappings' }))
    fireEvent.click(screen.getByText('user'))
    await waitFor(() =>
      expect(mockAddRealmRoles).toHaveBeenCalledWith({
        realm: 'master',
        id: 'u1',
        roles: [{ id: 'r2', name: 'user' }],
      })
    )
  })

  it('assigns a client role after picking a client', async () => {
    mockAddClientRoles.mockResolvedValue(undefined)
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Role Mappings' }))
    fireEvent.click(screen.getByText('Select a client'))
    fireEvent.click(screen.getByRole('option', { name: 'backend-api' }))
    fireEvent.click(screen.getByText('writer'))
    await waitFor(() =>
      expect(mockAddClientRoles).toHaveBeenCalledWith({
        realm: 'master',
        id: 'u1',
        clientId: 'c1',
        roles: [{ id: 'r4', name: 'writer' }],
      })
    )
  })
})

describe('UserDetailPage credentials tab', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  function openCredentialsTab() {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Credentials' }))
  }

  it('lists credentials with type label, user label, and priority', () => {
    openCredentialsTab()
    expect(screen.getByText('Password')).toBeInTheDocument()
    expect(screen.getByText('TOTP')).toBeInTheDocument()
    expect(screen.getByText('Primary password')).toBeInTheDocument()
    // The raw credential id is not rendered.
    expect(screen.queryByText('cred-1')).not.toBeInTheDocument()
    expect(screen.queryByText('cred-2')).not.toBeInTheDocument()
    expect(screen.getByText(/Priority: 1/)).toBeInTheDocument()
    expect(screen.getAllByText(/Created:/).length).toBe(2)
    // Enum descriptions surface as tooltips on the type label.
    expect(screen.getByText('Password')).toHaveAttribute('title', 'Password credential')
  })

  it('edits a credential label inline', async () => {
    const user = userEvent.setup()
    mockUpdateCredentialLabel.mockResolvedValue(undefined)
    openCredentialsTab()
    await user.click(screen.getAllByRole('button', { name: 'Edit label' })[0])
    const input = screen.getByLabelText('Credential label')
    expect((input as HTMLInputElement).value).toBe('Primary password')
    await user.clear(input)
    await user.type(input, 'Work laptop')
    await user.click(screen.getByRole('button', { name: 'Save label' }))
    await waitFor(() =>
      expect(mockUpdateCredentialLabel).toHaveBeenCalledWith({
        realm: 'master',
        id: 'u1',
        credentialId: 'cred-1',
        label: 'Work laptop',
      })
    )
  })

  it('deletes a credential after confirmation', async () => {
    const user = userEvent.setup()
    mockDeleteCredential.mockResolvedValue(undefined)
    openCredentialsTab()
    await user.click(screen.getAllByRole('button', { name: 'Delete credential' })[0])
    const dialog = screen.getByRole('dialog')
    expect(within(dialog).getByText(/last remaining credential/)).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: 'Delete' }))
    await waitFor(() =>
      expect(mockDeleteCredential).toHaveBeenCalledWith({
        realm: 'master',
        id: 'u1',
        credentialId: 'cred-1',
      })
    )
  })

  it('keeps the delete modal open when the API rejects the delete (last-credential guard)', async () => {
    const user = userEvent.setup()
    mockDeleteCredential.mockRejectedValue(new Error('cannot delete the last remaining credential'))
    openCredentialsTab()
    await user.click(screen.getAllByRole('button', { name: 'Delete credential' })[0])
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(mockDeleteCredential).toHaveBeenCalled())
    // The hook (mocked here) owns the error toast; the modal stays open.
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })

  it('moves a credential down via moveAfter', async () => {
    const user = userEvent.setup()
    mockMoveCredential.mockResolvedValue(undefined)
    openCredentialsTab()
    await user.click(screen.getAllByRole('button', { name: 'Move down' })[0])
    await waitFor(() =>
      expect(mockMoveCredential).toHaveBeenCalledWith({
        realm: 'master',
        id: 'u1',
        credentialId: 'cred-1',
        newPreviousCredentialId: 'cred-2',
      })
    )
  })

  it('moves a credential up via moveAfter on the neighbor', async () => {
    const user = userEvent.setup()
    mockMoveCredential.mockResolvedValue(undefined)
    openCredentialsTab()
    await user.click(screen.getAllByRole('button', { name: 'Move up' })[1])
    await waitFor(() =>
      expect(mockMoveCredential).toHaveBeenCalledWith({
        realm: 'master',
        id: 'u1',
        credentialId: 'cred-1',
        newPreviousCredentialId: 'cred-2',
      })
    )
  })
})

describe('UserDetailPage impersonation', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('requires confirmation and warns that impersonation is audited', async () => {
    const user = userEvent.setup()
    mockImpersonateUser.mockResolvedValue(undefined)
    renderPage()
    await user.click(screen.getByRole('button', { name: 'Impersonate' }))
    const dialog = screen.getByRole('dialog')
    expect(within(dialog).getByText(/audited/)).toBeInTheDocument()
    expect(mockImpersonateUser).not.toHaveBeenCalled()
    await user.click(within(dialog).getByRole('button', { name: 'Impersonate' }))
    await waitFor(() =>
      expect(mockImpersonateUser).toHaveBeenCalledWith({ realm: 'master', id: 'u1' })
    )
  })

  it('cancel closes the modal without calling the API', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.click(screen.getByRole('button', { name: 'Impersonate' }))
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Cancel' }))
    expect(mockImpersonateUser).not.toHaveBeenCalled()
  })
})

describe('UserDetailPage execute actions email', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('submits selected actions with optional redirect URI and lifespan', async () => {
    const user = userEvent.setup()
    mockExecuteActionsEmail.mockResolvedValue(undefined)
    renderPage()
    await user.click(screen.getByRole('button', { name: 'Execute Actions Email' }))
    const dialog = screen.getByRole('dialog')

    // Required actions render dynamically from serverinfo with descriptions.
    expect(within(dialog).getByText('User must update their password')).toBeInTheDocument()

    // Send is disabled until at least one action is selected.
    expect(within(dialog).getByRole('button', { name: 'Send Email' })).toBeDisabled()

    await user.click(within(dialog).getByRole('checkbox', { name: /Update Password/ }))
    await user.type(
      within(dialog).getByLabelText('Redirect URI (optional)'),
      'https://app.example.com/done'
    )
    await user.type(within(dialog).getByLabelText('Lifespan in seconds (optional)'), '600')
    await user.click(within(dialog).getByRole('button', { name: 'Send Email' }))

    await waitFor(() =>
      expect(mockExecuteActionsEmail).toHaveBeenCalledWith({
        realm: 'master',
        id: 'u1',
        actions: ['UPDATE_PASSWORD'],
        redirectUri: 'https://app.example.com/done',
        lifespan: 600,
      })
    )
  })

  it('omits optional fields when left blank', async () => {
    const user = userEvent.setup()
    mockExecuteActionsEmail.mockResolvedValue(undefined)
    renderPage()
    await user.click(screen.getByRole('button', { name: 'Execute Actions Email' }))
    const dialog = screen.getByRole('dialog')
    await user.click(within(dialog).getByRole('checkbox', { name: /Verify Email/ }))
    await user.click(within(dialog).getByRole('button', { name: 'Send Email' }))
    await waitFor(() =>
      expect(mockExecuteActionsEmail).toHaveBeenCalledWith({
        realm: 'master',
        id: 'u1',
        actions: ['VERIFY_EMAIL'],
        redirectUri: undefined,
        lifespan: undefined,
      })
    )
  })
})
