// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ClientEditPage from './ClientEditPage'

const mockCreateRole = vi.fn()
const mockDeleteRole = vi.fn()
const mockAssignDefault = vi.fn()
const mockNavigate = vi.fn()
const mockUpdateClient = vi.fn()

const baseClient = {
  id: 'c1',
  client_id: 'backend-api',
  protocol: 'openid-connect',
  enabled: true,
  public_client: false,
  full_scope_allowed: true,
  service_accounts_enabled: true,
}
let clientData: Record<string, unknown> = { ...baseClient }

vi.mock('../../state/authStore', () => ({
  useAuthStore: (selector: any) => selector({ currentRealm: 'master' }),
}))

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

vi.mock('../../api/hooks/useClients', () => ({
  useClient: () => ({
    data: clientData,
    isLoading: false,
    error: null,
  }),
  useUpdateClient: () => ({ mutateAsync: mockUpdateClient, isPending: false }),
  useDeleteClient: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useRotateClientSecret: () => ({ mutate: vi.fn(), mutateAsync: vi.fn(), isPending: false }),
  useGetClientSecret: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useClients: () => ({
    data: [{ id: 'c1', client_id: 'backend-api' }, { id: 'c2', client_id: 'frontend-app' }],
    isLoading: false,
  }),
  useClientRoles: () => ({
    data: [{ id: 'r1', name: 'reader', description: 'Read access', composite: false, client_role: true }],
    isLoading: false,
    error: null,
  }),
  useCreateClientRole: () => ({ mutateAsync: mockCreateRole, isPending: false }),
  useDeleteClientRole: () => ({ mutateAsync: mockDeleteRole, isPending: false }),
  useClientMappers: () => ({
    data: [{ id: 'm1', name: 'department', protocol_mapper: 'oidc-usermodel-attribute-mapper', config: {} }],
    isLoading: false,
    error: null,
  }),
  useCreateClientMapper: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useUpdateClientMapper: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useDeleteClientMapper: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useDefaultClientScopes: () => ({
    data: [{ id: 's1', name: 'profile', description: 'Profile claims' }],
    isLoading: false,
  }),
  useOptionalClientScopes: () => ({ data: [], isLoading: false }),
  useAssignDefaultClientScope: () => ({ mutateAsync: mockAssignDefault, isPending: false }),
  useUnassignDefaultClientScope: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useAssignOptionalClientScope: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useUnassignOptionalClientScope: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useScopeMappingRealmRoles: () => ({ data: [{ id: 'r9', name: 'admin' }], isLoading: false }),
  useAvailableScopeMappingRealmRoles: () => ({ data: [{ id: 'r8', name: 'user' }], isLoading: false }),
  useAddScopeMappingRealmRoles: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useRemoveScopeMappingRealmRoles: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useScopeMappingClientRoles: () => ({ data: [], isLoading: false }),
  useAvailableScopeMappingClientRoles: () => ({ data: [], isLoading: false }),
  useAddScopeMappingClientRoles: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useRemoveScopeMappingClientRoles: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useClientInstallation: () => ({
    data: {
      realm: 'master',
      'auth-server-url': 'http://localhost:8080/',
      'ssl-required': 'external',
      resource: 'backend-api',
      credentials: { secret: 's3cr3t' },
    },
    isLoading: false,
    error: null,
  }),
}))

vi.mock('../../api/hooks/useClientScopes', () => ({
  useClientScopes: () => ({
    data: [
      { id: 's1', name: 'profile' },
      { id: 's2', name: 'email' },
    ],
    isLoading: false,
  }),
}))

vi.mock('../../api/hooks/useServerInfo', () => ({
  useServerInfo: () => ({
    data: {
      protocols: [{ id: 'openid-connect', name: 'OpenID Connect', description: 'OIDC protocol' }],
      client_authenticator_types: [
        { id: 'client-secret', name: 'Client Secret', description: 'Authenticate with client ID and secret' },
        { id: 'client-jwt', name: 'Client JWT', description: 'Authenticate with signed JWT assertion' },
        { id: 'client-secret-jwt', name: 'Client Secret JWT', description: 'Authenticate with HMAC-signed JWT using client secret' },
        { id: 'client-x509', name: 'Client X.509', description: 'Authenticate with X.509 client certificate' },
      ],
      mapper_types: [
        { id: 'oidc-usermodel-attribute-mapper', name: 'User Attribute', description: 'Map a user attribute' },
      ],
      subject_types: [
        { id: 'public', name: 'Public', description: 'Every client receives the same subject identifier (the internal user id)' },
        { id: 'pairwise', name: 'Pairwise', description: 'Subject identifiers are derived per sector (OIDC Core §8); different sectors see unlinkable identifiers for the same user' },
      ],
      client_installations: [
        { id: 'keycloak-oidc-keycloak-json', protocol: 'openid-connect', display_type: 'Keycloak OIDC JSON', help_text: 'keycloak.json file used by Keycloak-compatible OIDC client adapters', filename: 'keycloak.json', media_type: 'application/json', download_only: false },
        { id: 'generic-oidc-json', protocol: 'openid-connect', display_type: 'Generic OIDC JSON', help_text: 'Product-neutral OIDC client configuration', filename: 'oidc-client-config.json', media_type: 'application/json', download_only: false },
      ],
    },
    isLoading: false,
  }),
}))

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/admin/clients/c1']}>
        <Routes>
          <Route path="/admin/clients/:id" element={<ClientEditPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  )
}

function optionByTitle(title: string) {
  const opt = screen.getAllByRole('option').find((o) => o.getAttribute('title') === title)
  if (!opt) throw new Error(`no option with title "${title}"`)
  return opt
}

describe('ClientEditPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    clientData = { ...baseClient }
  })

  it('renders all five tabs', () => {
    renderPage()
    for (const tab of ['Settings', 'Roles', 'Mappers', 'Client Scopes', 'Scope Mappings']) {
      expect(screen.getByRole('tab', { name: tab })).toBeInTheDocument()
    }
  })

  it('shows the service accounts switch on the settings tab', () => {
    renderPage()
    const toggle = screen.getByLabelText('Service Accounts Enabled')
    expect(toggle).toBeChecked()
  })

  it('lists client roles and creates a new one', async () => {
    const user = userEvent.setup()
    mockCreateRole.mockResolvedValue({ id: 'r2' })
    renderPage()
    await user.click(screen.getByRole('tab', { name: 'Roles' }))

    expect(screen.getByText('reader')).toBeInTheDocument()
    expect(screen.getByText('Read access')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /Create Role/ }))
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'writer' } })
    fireEvent.change(screen.getByLabelText('Description'), { target: { value: 'Write access' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(mockCreateRole).toHaveBeenCalled())
    expect(mockCreateRole.mock.calls[0][0]).toEqual({
      realm: 'master',
      clientId: 'c1',
      body: { name: 'writer', description: 'Write access' },
    })
  })

  it('deletes a client role after confirmation', async () => {
    const user = userEvent.setup()
    mockDeleteRole.mockResolvedValue(undefined)
    renderPage()
    await user.click(screen.getByRole('tab', { name: 'Roles' }))
    fireEvent.click(screen.getByRole('button', { name: 'Delete role reader' }))
    const dialog = screen.getByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }))
    await waitFor(() =>
      expect(mockDeleteRole).toHaveBeenCalledWith({ realm: 'master', clientId: 'c1', roleName: 'reader' })
    )
  })

  it('lists mappers on the mappers tab', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.click(screen.getByRole('tab', { name: 'Mappers' }))
    expect(screen.getByText('department')).toBeInTheDocument()
    expect(screen.getByText('User Attribute')).toBeInTheDocument()
  })

  it('assigns a default client scope from the picker', async () => {
    const user = userEvent.setup()
    mockAssignDefault.mockResolvedValue(undefined)
    renderPage()
    await user.click(screen.getByRole('tab', { name: 'Client Scopes' }))

    // the default list already shows the assigned scope
    expect(screen.getByText('profile')).toBeInTheDocument()

    // first picker is the Default Client Scopes card
    fireEvent.click(screen.getAllByText('Select a scope to add')[0])
    fireEvent.click(screen.getByRole('option', { name: 'email' }))
    fireEvent.click(screen.getAllByRole('button', { name: /Add/ })[0])

    await waitFor(() =>
      expect(mockAssignDefault).toHaveBeenCalledWith({ realm: 'master', clientId: 'c1', scopeId: 's2' })
    )
  })

  it('shows the full-scope info note on the scope mappings tab', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.click(screen.getByRole('tab', { name: 'Scope Mappings' }))
    expect(screen.getByText(/Full scope is allowed/)).toBeInTheDocument()
    // realm roles pickers render
    expect(screen.getByText('admin')).toBeInTheDocument()
    expect(screen.getByText('user')).toBeInTheDocument()
  })

  it('lists the client authenticator options from serverinfo with descriptions', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.click(screen.getByLabelText('Client Authenticator'))

    const option = optionByTitle('Authenticate with signed JWT assertion')
    // description is surfaced both as the option subtitle and its tooltip
    expect(within(option).getByText('Authenticate with signed JWT assertion')).toBeInTheDocument()
    expect(optionByTitle('Authenticate with client ID and secret')).toBeInTheDocument()
    expect(optionByTitle('Authenticate with HMAC-signed JWT using client secret')).toBeInTheDocument()
    expect(optionByTitle('Authenticate with X.509 client certificate')).toBeInTheDocument()
  })

  it('shows JWKS fields when client-jwt is selected and saves the inline JWKS attributes', async () => {
    const user = userEvent.setup()
    mockUpdateClient.mockResolvedValue(undefined)
    renderPage()

    // no JWKS fields for the default client-secret authenticator
    expect(screen.queryByText('JWKS Source')).not.toBeInTheDocument()

    await user.click(screen.getByLabelText('Client Authenticator'))
    await user.click(optionByTitle('Authenticate with signed JWT assertion'))

    // inline source is the default; the URL input stays hidden
    expect(screen.getByRole('button', { name: 'Inline' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByRole('button', { name: 'URL' })).toHaveAttribute('aria-pressed', 'false')
    expect(screen.queryByLabelText('JWKS URL')).not.toBeInTheDocument()

    const jwksJson = '{"keys":[{"kty":"RSA","kid":"k1","n":"abc","e":"AQAB"}]}'
    fireEvent.change(screen.getByLabelText('JWKS (JSON)'), { target: { value: jwksJson } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(mockUpdateClient).toHaveBeenCalled())
    const body = mockUpdateClient.mock.calls[0][0].body
    expect(body.client_authenticator_type).toBe('client-jwt')
    expect(body.attributes['use.jwks.string']).toBe('true')
    expect(body.attributes['jwks.string']).toBe(jwksJson)
    expect(body.attributes['use.jwks.url']).toBeUndefined()
    expect(body.attributes['jwks.url']).toBeUndefined()
  })

  it('switches the JWKS source to URL and replaces the stored attribute keys', async () => {
    const user = userEvent.setup()
    mockUpdateClient.mockResolvedValue(undefined)
    clientData = {
      ...baseClient,
      client_authenticator_type: 'client-jwt',
      attributes: {
        'use.jwks.string': 'true',
        'jwks.string': '{"keys":[]}',
        'other.key': 'keep-me',
      },
    }
    renderPage()

    // inline source and the stored JWKS are preselected from the attributes
    expect(screen.getByRole('button', { name: 'Inline' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByLabelText('JWKS (JSON)')).toHaveValue('{"keys":[]}')

    await user.click(screen.getByRole('button', { name: 'URL' }))
    expect(screen.queryByLabelText('JWKS (JSON)')).not.toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('JWKS URL'), {
      target: { value: 'https://keys.example.com/jwks' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(mockUpdateClient).toHaveBeenCalled())
    const body = mockUpdateClient.mock.calls[0][0].body
    expect(body.attributes['use.jwks.url']).toBe('true')
    expect(body.attributes['jwks.url']).toBe('https://keys.example.com/jwks')
    expect(body.attributes['use.jwks.string']).toBeUndefined()
    expect(body.attributes['jwks.string']).toBeUndefined()
    // unrelated attributes round-trip untouched
    expect(body.attributes['other.key']).toBe('keep-me')
  })

  it('strips the JWKS attributes when a non-JWT authenticator is selected', async () => {
    const user = userEvent.setup()
    mockUpdateClient.mockResolvedValue(undefined)
    clientData = {
      ...baseClient,
      client_authenticator_type: 'client-jwt',
      attributes: { 'use.jwks.string': 'true', 'jwks.string': '{"keys":[]}' },
    }
    renderPage()

    await user.click(screen.getByLabelText('Client Authenticator'))
    await user.click(optionByTitle('Authenticate with HMAC-signed JWT using client secret'))
    expect(screen.queryByText('JWKS Source')).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(mockUpdateClient).toHaveBeenCalled())
    const body = mockUpdateClient.mock.calls[0][0].body
    expect(body.client_authenticator_type).toBe('client-secret-jwt')
    expect(body.attributes['use.jwks.string']).toBeUndefined()
    expect(body.attributes['jwks.string']).toBeUndefined()
    expect(body.attributes['use.jwks.url']).toBeUndefined()
    expect(body.attributes['jwks.url']).toBeUndefined()
  })

  it('hides the authenticator and JWKS fields for public clients and strips JWKS keys on save', async () => {
    mockUpdateClient.mockResolvedValue(undefined)
    clientData = {
      ...baseClient,
      public_client: true,
      client_authenticator_type: 'client-jwt',
      attributes: { 'use.jwks.string': 'true', 'jwks.string': '{"keys":[]}' },
    }
    renderPage()

    expect(screen.queryByLabelText('Client Authenticator')).not.toBeInTheDocument()
    expect(screen.queryByText('JWKS Source')).not.toBeInTheDocument()
    // the client secret box follows the same public-client gating
    expect(screen.queryByRole('button', { name: 'View Secret' })).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(mockUpdateClient).toHaveBeenCalled())
    const body = mockUpdateClient.mock.calls[0][0].body
    expect(body.attributes['use.jwks.string']).toBeUndefined()
    expect(body.attributes['jwks.string']).toBeUndefined()
  })

  it('defaults the token exchange switch off and persists the attribute when enabled', async () => {
    const user = userEvent.setup()
    mockUpdateClient.mockResolvedValue(undefined)
    clientData = { ...baseClient, attributes: { 'other.key': 'keep-me' } }
    renderPage()

    const toggle = screen.getByLabelText('Token Exchange Enabled')
    expect(toggle).not.toBeChecked()

    await user.click(toggle)
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(mockUpdateClient).toHaveBeenCalled())
    const body = mockUpdateClient.mock.calls[0][0].body
    expect(body.attributes['token.exchange.enabled']).toBe('true')
    // unrelated attributes round-trip untouched
    expect(body.attributes['other.key']).toBe('keep-me')
  })

  it('preselects the token exchange switch from attributes and strips the key when disabled', async () => {
    const user = userEvent.setup()
    mockUpdateClient.mockResolvedValue(undefined)
    clientData = { ...baseClient, attributes: { 'token.exchange.enabled': 'true' } }
    renderPage()

    const toggle = screen.getByLabelText('Token Exchange Enabled')
    expect(toggle).toBeChecked()

    await user.click(toggle)
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(mockUpdateClient).toHaveBeenCalled())
    const body = mockUpdateClient.mock.calls[0][0].body
    expect(body.attributes['token.exchange.enabled']).toBeUndefined()
  })

  it('lists the subject type options from serverinfo with descriptions', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.click(screen.getByLabelText('Subject Type'))

    const option = optionByTitle(
      'Subject identifiers are derived per sector (OIDC Core §8); different sectors see unlinkable identifiers for the same user'
    )
    // description is surfaced both as the option subtitle and its tooltip
    expect(
      within(option).getByText(
        'Subject identifiers are derived per sector (OIDC Core §8); different sectors see unlinkable identifiers for the same user'
      )
    ).toBeInTheDocument()
    expect(
      optionByTitle('Every client receives the same subject identifier (the internal user id)')
    ).toBeInTheDocument()
  })

  it('reveals the sector identifier URI field for pairwise and persists both attributes', async () => {
    const user = userEvent.setup()
    mockUpdateClient.mockResolvedValue(undefined)
    clientData = { ...baseClient, attributes: { 'other.key': 'keep-me' } }
    renderPage()

    // public is the default; the sector URI field stays hidden
    expect(screen.queryByLabelText('Sector Identifier URI')).not.toBeInTheDocument()

    await user.click(screen.getByLabelText('Subject Type'))
    await user.click(
      optionByTitle(
        'Subject identifiers are derived per sector (OIDC Core §8); different sectors see unlinkable identifiers for the same user'
      )
    )

    fireEvent.change(screen.getByLabelText('Sector Identifier URI'), {
      target: { value: 'https://app.example.com/sector.json' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(mockUpdateClient).toHaveBeenCalled())
    const body = mockUpdateClient.mock.calls[0][0].body
    expect(body.attributes['subject_type']).toBe('pairwise')
    expect(body.attributes['sector_identifier_uri']).toBe('https://app.example.com/sector.json')
    // unrelated attributes round-trip untouched
    expect(body.attributes['other.key']).toBe('keep-me')
  })

  it('preselects pairwise from attributes and strips both keys when switched back to public', async () => {
    const user = userEvent.setup()
    mockUpdateClient.mockResolvedValue(undefined)
    clientData = {
      ...baseClient,
      attributes: {
        subject_type: 'pairwise',
        sector_identifier_uri: 'https://app.example.com/sector.json',
      },
    }
    renderPage()

    // the stored pairwise attributes are preselected
    expect(screen.getByLabelText('Sector Identifier URI')).toHaveValue('https://app.example.com/sector.json')

    await user.click(screen.getByLabelText('Subject Type'))
    await user.click(
      optionByTitle('Every client receives the same subject identifier (the internal user id)')
    )
    expect(screen.queryByLabelText('Sector Identifier URI')).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(mockUpdateClient).toHaveBeenCalled())
    const body = mockUpdateClient.mock.calls[0][0].body
    expect(body.attributes['subject_type']).toBeUndefined()
    expect(body.attributes['sector_identifier_uri']).toBeUndefined()
  })

  it('opens the download dialog with formats from serverinfo and previews the adapter config', async () => {
    const user = userEvent.setup()
    renderPage()

    await user.click(screen.getByRole('button', { name: /Download Config/ }))
    const dialog = screen.getByRole('dialog')

    // the format dropdown defaults to the first provider from serverinfo
    expect(within(dialog).getByLabelText('Format')).toHaveTextContent('Keycloak OIDC JSON')

    // the preview shows the pretty-printed adapter config
    const preview = within(dialog).getByLabelText('Details')
    expect(preview).toHaveValue(
      JSON.stringify(
        {
          realm: 'master',
          'auth-server-url': 'http://localhost:8080/',
          'ssl-required': 'external',
          resource: 'backend-api',
          credentials: { secret: 's3cr3t' },
        },
        null,
        2
      )
    )

    // both formats are listed, with the help text surfaced as description
    await user.click(within(dialog).getByLabelText('Format'))
    const generic = optionByTitle('Product-neutral OIDC client configuration')
    expect(within(generic).getByText('Generic OIDC JSON')).toBeInTheDocument()
    expect(optionByTitle('keycloak.json file used by Keycloak-compatible OIDC client adapters')).toBeInTheDocument()

    await user.click(generic)
    expect(within(dialog).getByLabelText('Format')).toHaveTextContent('Generic OIDC JSON')
  })

  it('downloads the config as a file named after the selected provider', async () => {
    const user = userEvent.setup()
    const createObjectURL = vi.fn(() => 'blob:mock-url')
    const revokeObjectURL = vi.fn()
    const originalCreate = URL.createObjectURL
    const originalRevoke = URL.revokeObjectURL
    URL.createObjectURL = createObjectURL
    URL.revokeObjectURL = revokeObjectURL
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    try {
      renderPage()
      await user.click(screen.getByRole('button', { name: /Download Config/ }))
      const dialog = screen.getByRole('dialog')

      await user.click(within(dialog).getByRole('button', { name: /Download/ }))

      expect(createObjectURL).toHaveBeenCalled()
      const blob = createObjectURL.mock.calls[0][0] as Blob
      expect(blob.type).toBe('application/json')
      expect(clickSpy).toHaveBeenCalled()
      expect(revokeObjectURL).toHaveBeenCalledWith('blob:mock-url')
    } finally {
      URL.createObjectURL = originalCreate
      URL.revokeObjectURL = originalRevoke
      clickSpy.mockRestore()
    }
  })
})
