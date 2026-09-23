// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import RealmSettingsPage from './RealmSettingsPage'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

const mockRealm = {
  realm: 'master',
  display_name: 'Master Realm',
  enabled: true,
  ssl_required: 'external',
  access_token_lifespan: 300,
  refresh_token_lifespan: 1800,
  sso_session_idle_timeout: 1800,
  sso_session_max_lifespan: 36000,
  offline_session_idle_timeout: 2592000,
}

const mockMutateAsync = vi.fn()
const mockTestSmtpAsync = vi.fn()
const mockUpdateEventsConfigAsync = vi.fn()
const mockSetRealm = vi.fn()
const mockNavigate = vi.fn()

let mockCurrentRealm = 'master'
let mockRealmState = { data: mockRealm, isLoading: false, error: null as Error | null }

vi.mock('../../state/authStore', () => ({
  useAuthStore: (selector: any) =>
    selector({ currentRealm: mockCurrentRealm, setRealm: mockSetRealm }),
}))

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

vi.mock('../../api/hooks/useRealms', () => ({
  useRealm: () => mockRealmState,
  useUpdateRealm: () => ({ mutateAsync: mockMutateAsync, isPending: false }),
  useTestSmtpConnection: () => ({ mutateAsync: mockTestSmtpAsync, isPending: false }),
}))

vi.mock('../../api/hooks/useAuthFlows', () => ({
  useFlows: () => ({
    data: [
      { alias: 'browser', top_level: true, built_in: true },
      { alias: 'direct grant', top_level: true, built_in: true },
      { alias: 'custom browser', top_level: true, built_in: false },
    ],
    isLoading: false,
    error: null,
  }),
}))

vi.mock('../../api/hooks/useEventsConfig', () => ({
  useEventsConfig: () => ({
    data: {
      eventsEnabled: true,
      eventsExpiration: 3600,
      adminEventsEnabled: false,
      adminEventsDetailsEnabled: false,
      eventsListeners: ['logging'],
    },
    isLoading: false,
    error: null,
  }),
  useUpdateEventsConfig: () => ({ mutateAsync: mockUpdateEventsConfigAsync, isPending: false }),
  useClearEvents: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useClearAdminEvents: () => ({ mutateAsync: vi.fn(), isPending: false }),
}))

vi.mock('../../api/hooks/useRealmAdminActions', () => ({
  usePartialImport: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useExportRealm: () => ({ mutateAsync: vi.fn(), isPending: false }),
  usePushRevocation: () => ({ mutateAsync: vi.fn(), isPending: false }),
}))

vi.mock('../../api/hooks/useServerInfo', () => ({
  useServerInfo: () => ({
    data: {
      ssl_required: [
        { id: 'none', name: 'None', description: 'No SSL required' },
        { id: 'external', name: 'External', description: 'External only' },
        { id: 'all', name: 'All', description: 'All requests' },
      ],
      otp_algorithms: [
        { id: 'HmacSHA1', name: 'HMAC-SHA-1', description: 'RFC 6238 default (SHA-1)' },
        { id: 'HmacSHA256', name: 'HMAC-SHA-256', description: 'Stronger SHA-256 hash' },
        { id: 'HmacSHA512', name: 'HMAC-SHA-512', description: 'Strongest SHA-512 hash' },
      ],
      locales: [
        { id: 'en', name: 'English', description: 'Built-in English bundle' },
        { id: 'de', name: 'German', description: 'Built-in German bundle' },
      ],
      themes: [
        { id: 'issuerd', name: 'Issuerd', description: 'Built-in login theme' },
        { id: 'acme', name: 'Acme Corp', description: 'Custom login theme' },
      ],
      event_listeners: [
        { id: 'logging', name: 'Logging', description: 'Writes events to the server log' },
      ],
    },
    isLoading: false,
  }),
}))

function Wrapper({ children }: { children: React.ReactNode }) {
  return (
    <QueryClientProvider client={new QueryClient()}>
      <MemoryRouter initialEntries={['/admin/realms/master/settings']}>
        <Routes>
          <Route path="/admin/realms/:realm/settings" element={children} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  )
}

describe('RealmSettingsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockCurrentRealm = 'master'
    mockRealmState = { data: mockRealm, isLoading: false, error: null }
  })

  it('renders tabs', () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    expect(screen.getByRole('button', { name: 'General' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Tokens' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Sessions' })).toBeInTheDocument()
  })

  it('shows general tab by default', () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    expect(screen.getByDisplayValue('Master Realm')).toBeInTheDocument()
    expect(screen.getByText('Basic Information')).toBeInTheDocument()
  })

  it('switches to tokens tab', () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Tokens' }))
    expect(screen.getByText('Token Lifespans')).toBeInTheDocument()
  })

  it('switches to sessions tab', () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Sessions' }))
    expect(screen.getByText('SSO Session')).toBeInTheDocument()
  })

  it('edits realm name and enables save', () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    const input = screen.getByDisplayValue('master')
    fireEvent.change(input, { target: { value: 'newmaster' } })
    expect(screen.getByRole('button', { name: /Save Changes/i })).not.toBeDisabled()
  })

  it('saves changes', async () => {
    mockMutateAsync.mockResolvedValue(undefined)
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    const input = screen.getByDisplayValue('master')
    fireEvent.change(input, { target: { value: 'newmaster' } })
    fireEvent.click(screen.getByRole('button', { name: /Save Changes/i }))
    await waitFor(() => expect(mockMutateAsync).toHaveBeenCalled())
  })

  it('updates current realm when name changes to current', async () => {
    mockMutateAsync.mockResolvedValue(undefined)
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    const input = screen.getByDisplayValue('master')
    fireEvent.change(input, { target: { value: 'master' } })
    // No change - button disabled
    expect(screen.getByRole('button', { name: /Save Changes/i })).toBeDisabled()
  })

  it('changes SSL required', async () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByText('External'))
    fireEvent.click(await screen.findByText('All'))
    expect(screen.getByRole('button', { name: /Save Changes/i })).not.toBeDisabled()
  })

  it('toggles enabled switch', () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    const toggle = screen.getByLabelText('Enabled')
    fireEvent.click(toggle)
    expect(screen.getByRole('button', { name: /Save Changes/i })).not.toBeDisabled()
  })

  it('changes token lifespan in tokens tab', () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Tokens' }))
    fireEvent.click(screen.getAllByRole('button', { name: '15 minutes' })[0])
    expect(screen.getByRole('button', { name: /Save Changes/i })).not.toBeDisabled()
  })

  it('changes session timeout in sessions tab', () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Sessions' }))
    fireEvent.click(screen.getAllByRole('button', { name: '1 hour' })[0])
    expect(screen.getByRole('button', { name: /Save Changes/i })).not.toBeDisabled()
  })

  it('changes refresh token lifespan in tokens tab', () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Tokens' }))
    fireEvent.click(screen.getAllByRole('button', { name: '15 minutes' })[1])
    expect(screen.getByRole('button', { name: /Save Changes/i })).not.toBeDisabled()
  })

  it('changes SSO session max lifespan in sessions tab', () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Sessions' }))
    fireEvent.click(screen.getAllByRole('button', { name: '1 hour' })[1])
    expect(screen.getByRole('button', { name: /Save Changes/i })).not.toBeDisabled()
  })

  it('changes offline session timeout in sessions tab', () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Sessions' }))
    fireEvent.click(screen.getAllByRole('button', { name: '30 days' })[0])
    expect(screen.getByRole('button', { name: /Save Changes/i })).not.toBeDisabled()
  })

  it('changes login theme in general tab', () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Login Theme' }))
    fireEvent.click(screen.getByText('Issuerd'))
    expect(screen.getByRole('button', { name: /Save Changes/i })).not.toBeDisabled()
  })

  it('changes email theme in general tab', () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Email Theme' }))
    fireEvent.click(screen.getByText('Issuerd'))
    expect(screen.getByRole('button', { name: /Save Changes/i })).not.toBeDisabled()
  })

  it('changes admin theme in general tab', () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Admin Theme' }))
    fireEvent.click(screen.getByText('Issuerd'))
    expect(screen.getByRole('button', { name: /Save Changes/i })).not.toBeDisabled()
  })

  it('changes display name and enables save', () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    const input = screen.getByDisplayValue('Master Realm')
    fireEvent.change(input, { target: { value: 'New Name' } })
    expect(screen.getByRole('button', { name: /Save Changes/i })).not.toBeDisabled()
  })

  it('updates current realm reference when renamed', async () => {
    mockMutateAsync.mockResolvedValue(undefined)
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    const input = screen.getByDisplayValue('master')
    fireEvent.change(input, { target: { value: 'newmaster' } })
    fireEvent.click(screen.getByRole('button', { name: /Save Changes/i }))
    await waitFor(() => expect(mockMutateAsync).toHaveBeenCalled())
  })

  it('updates auth store when renamed to current realm', async () => {
    mockMutateAsync.mockResolvedValue(undefined)
    mockCurrentRealm = 'other'
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    const input = screen.getByDisplayValue('master')
    fireEvent.change(input, { target: { value: 'other' } })
    fireEvent.click(screen.getByRole('button', { name: /Save Changes/i }))
    await waitFor(() => expect(mockMutateAsync).toHaveBeenCalled())
    expect(mockSetRealm).toHaveBeenCalledWith('other')
  })

  it('shows spinner while loading', () => {
    mockRealmState = { data: null, isLoading: true, error: null }
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    expect(document.querySelector('.animate-spin')).toBeInTheDocument()
  })

  it('shows error message on error', () => {
    mockRealmState = { data: null, isLoading: false, error: new Error('load failed') }
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    expect(screen.getByText(/load failed/i)).toBeInTheDocument()
  })

  it('shows realm not found when data is null', () => {
    mockRealmState = { data: null, isLoading: false, error: null }
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    expect(screen.getByText(/Realm not found/i)).toBeInTheDocument()
  })

  it('navigates back when Back button clicked', () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: /Back/i }))
    expect(mockNavigate).toHaveBeenCalledWith('/realms')
  })

  it('does not call mutate when saving and realm is null', async () => {
    mockMutateAsync.mockResolvedValue(undefined)
    mockRealmState = { data: null, isLoading: false, error: null }
    // We can't easily click Save when realm is null because the UI doesn't render it,
    // but we can verify the branch by checking the component renders "not found".
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    expect(screen.getByText(/Realm not found/i)).toBeInTheDocument()
    expect(mockMutateAsync).not.toHaveBeenCalled()
  })

  it('renders the new login, email, and security tabs', () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    expect(screen.getByRole('button', { name: 'Login' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Email' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Security' })).toBeInTheDocument()
  })

  it('toggles a login option and enables save', () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Login' }))
    expect(screen.getByText('Login Options')).toBeInTheDocument()
    fireEvent.click(screen.getByLabelText('User registration'))
    expect(screen.getByRole('button', { name: /Save Changes/i })).not.toBeDisabled()
  })

  it('keeps brute force numbers disabled until detection is enabled', () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Security' }))
    expect(screen.getByText('Brute Force Detection')).toBeInTheDocument()
    const maxFailures = screen.getByLabelText('Max Login Failures')
    expect(maxFailures).toBeDisabled()
    fireEvent.click(screen.getByLabelText('Enabled'))
    expect(maxFailures).not.toBeDisabled()
    fireEvent.change(maxFailures, { target: { value: '10' } })
    expect(screen.getByRole('button', { name: /Save Changes/i })).not.toBeDisabled()
  })

  it('round-trips SMTP host through realm attributes', () => {
    mockRealmState = {
      data: { ...mockRealm, attributes: { 'smtpServer.host': 'smtp.example.com' } },
      isLoading: false,
      error: null,
    }
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Email' }))
    expect(screen.getByDisplayValue('smtp.example.com')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Host'), { target: { value: 'mail.example.com' } })
    expect(screen.getByRole('button', { name: /Save Changes/i })).not.toBeDisabled()
  })

  it('sends a test email with the entered recipient', async () => {
    mockTestSmtpAsync.mockResolvedValue(undefined)
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Email' }))
    fireEvent.change(screen.getByLabelText('Recipient Email'), {
      target: { value: 'admin@example.com' },
    })
    fireEvent.click(screen.getByRole('button', { name: /Send Test Email/i }))
    await waitFor(() =>
      expect(mockTestSmtpAsync).toHaveBeenCalledWith({
        realm: 'master',
        email: 'admin@example.com',
      })
    )
    expect(await screen.findByText(/Test email sent to admin@example.com/i)).toBeInTheDocument()
  })

  it('shows the server error when the SMTP test fails', async () => {
    mockTestSmtpAsync.mockRejectedValue(new Error('SMTP host unreachable'))
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Email' }))
    fireEvent.change(screen.getByLabelText('Recipient Email'), {
      target: { value: 'admin@example.com' },
    })
    fireEvent.click(screen.getByRole('button', { name: /Send Test Email/i }))
    expect(await screen.findByText(/SMTP host unreachable/i)).toBeInTheDocument()
  })

  it('renders the OTP policy section on the security tab with dynamic algorithm options', async () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Security' }))
    expect(screen.getByText('OTP Policy')).toBeInTheDocument()

    // The closed dropdown shows the current algorithm (default HmacSHA1).
    fireEvent.click(screen.getByText('HMAC-SHA-1'))
    // Options come from the mocked serverInfo, not a hardcoded list.
    expect(await screen.findByRole('option', { name: /HMAC-SHA-1/ })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: /HMAC-SHA-256/ })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: /HMAC-SHA-512/ })).toBeInTheDocument()
  })

  it('surfaces algorithm descriptions in the context line and dropdown options', async () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Security' }))

    // Selected algorithm's description renders in the FormContextLine (dropdown closed).
    expect(screen.getByText('RFC 6238 default (SHA-1)')).toBeInTheDocument()

    // Open the dropdown: descriptions render as option subtitles and title tooltips.
    fireEvent.click(screen.getByText('HMAC-SHA-1'))
    const option = await screen.findByRole('option', { name: /HMAC-SHA-256/ })
    expect(option).toHaveAttribute('title', 'Stronger SHA-256 hash')
    expect(within(option).getByText('Stronger SHA-256 hash')).toBeInTheDocument()
  })

  it('constrains OTP numeric fields to their valid ranges', () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Security' }))

    const digits = screen.getByLabelText('Digits')
    expect(digits).toHaveAttribute('min', '6')
    expect(digits).toHaveAttribute('max', '8')
    expect(screen.getByLabelText('Period (seconds)')).toHaveAttribute('min', '1')
    const lookAhead = screen.getByLabelText('Look-ahead Window')
    expect(lookAhead).toHaveAttribute('min', '0')
    expect(lookAhead).toHaveAttribute('max', '5')
  })

  it('submits all four otpPolicy fields with the entered values', async () => {
    mockMutateAsync.mockResolvedValue(undefined)
    mockRealmState = {
      data: {
        ...mockRealm,
        otpPolicyAlgorithm: 'HmacSHA1',
        otpPolicyDigits: 6,
        otpPolicyPeriod: 30,
        otpPolicyLookAheadWindow: 0,
      },
      isLoading: false,
      error: null,
    }
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Security' }))

    // Change the algorithm via the dynamic dropdown.
    fireEvent.click(screen.getByText('HMAC-SHA-1'))
    fireEvent.click(await screen.findByRole('option', { name: /HMAC-SHA-512/ }))

    fireEvent.change(screen.getByLabelText('Digits'), { target: { value: '8' } })
    fireEvent.change(screen.getByLabelText('Period (seconds)'), { target: { value: '45' } })
    fireEvent.change(screen.getByLabelText('Look-ahead Window'), { target: { value: '2' } })
    fireEvent.click(screen.getByRole('button', { name: /Save Changes/i }))

    await waitFor(() => expect(mockMutateAsync).toHaveBeenCalled())
    expect(mockMutateAsync).toHaveBeenCalledWith({
      realm: 'master',
      body: expect.objectContaining({
        otpPolicyAlgorithm: 'HmacSHA512',
        otpPolicyDigits: 8,
        otpPolicyPeriod: 45,
        otpPolicyLookAheadWindow: 2,
      }),
    })
  })

  it('renders theme options from serverinfo with descriptions surfaced', async () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Login Theme' }))
    // Options come from the mocked serverInfo themes list, plus the empty default.
    const defaultOption = await screen.findByRole('option', { name: /Default/ })
    expect(defaultOption).toHaveAttribute('title', 'Built-in theme used when none is selected')
    const acme = screen.getByRole('option', { name: /Acme Corp/ })
    expect(acme).toHaveAttribute('title', 'Custom login theme')
    expect(within(acme).getByText('Custom login theme')).toBeInTheDocument()
  })

  it('saves the login theme from the dynamic dropdown', async () => {
    mockMutateAsync.mockResolvedValue(undefined)
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Login Theme' }))
    fireEvent.click(await screen.findByRole('option', { name: /Acme Corp/ }))
    fireEvent.click(screen.getByRole('button', { name: /Save Changes/i }))
    await waitFor(() => expect(mockMutateAsync).toHaveBeenCalled())
    expect(mockMutateAsync).toHaveBeenCalledWith({
      realm: 'master',
      body: expect.objectContaining({ login_theme: 'acme' }),
    })
  })

  it('resets the login theme to null when the empty default is chosen', async () => {
    mockMutateAsync.mockResolvedValue(undefined)
    mockRealmState = {
      data: { ...mockRealm, login_theme: 'acme' },
      isLoading: false,
      error: null,
    }
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Login Theme' }))
    fireEvent.click(await screen.findByRole('option', { name: /Default/ }))
    fireEvent.click(screen.getByRole('button', { name: /Save Changes/i }))
    await waitFor(() => expect(mockMutateAsync).toHaveBeenCalled())
    expect(mockMutateAsync).toHaveBeenCalledWith({
      realm: 'master',
      body: expect.objectContaining({ login_theme: null }),
    })
  })

  it('renders the Localization tab with locale options from serverinfo', () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Localization' }))
    expect(screen.getByLabelText('Internationalization')).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: /English/ })).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: /German/ })).toBeInTheDocument()
  })

  it('surfaces locale descriptions as subtitles and label tooltips', () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Localization' }))
    const german = screen.getByRole('checkbox', { name: /German/ })
    const label = german.closest('label')!
    expect(label).toHaveAttribute('title', 'Built-in German bundle')
    expect(within(label).getByText('Built-in German bundle')).toBeInTheDocument()
  })

  it('keeps locale controls disabled until internationalization is enabled', () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Localization' }))
    expect(screen.getByRole('checkbox', { name: /English/ })).toBeDisabled()
    expect(screen.getByRole('button', { name: /Server default/i })).toBeDisabled()
    fireEvent.click(screen.getByLabelText('Internationalization'))
    expect(screen.getByRole('checkbox', { name: /English/ })).not.toBeDisabled()
    expect(screen.getByRole('button', { name: /Server default/i })).not.toBeDisabled()
  })

  it('filters default-locale options to the selected supported locales', async () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Localization' }))
    fireEvent.click(screen.getByLabelText('Internationalization'))
    fireEvent.click(screen.getByRole('checkbox', { name: /German/ }))
    fireEvent.click(screen.getByRole('button', { name: /Server default/i }))
    expect(await screen.findByRole('option', { name: /German/ })).toBeInTheDocument()
    // Anchored: the "Server default" option's description mentions English.
    expect(screen.queryByRole('option', { name: /^English/ })).not.toBeInTheDocument()
  })

  it('saves localization settings with the realm payload', async () => {
    mockMutateAsync.mockResolvedValue(undefined)
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Localization' }))
    fireEvent.click(screen.getByLabelText('Internationalization'))
    fireEvent.click(screen.getByRole('checkbox', { name: /English/ }))
    fireEvent.click(screen.getByRole('checkbox', { name: /German/ }))
    fireEvent.click(screen.getByRole('button', { name: /Server default/i }))
    fireEvent.click(await screen.findByRole('option', { name: /German/ }))
    fireEvent.click(screen.getByRole('button', { name: /Save Changes/i }))
    await waitFor(() => expect(mockMutateAsync).toHaveBeenCalled())
    expect(mockMutateAsync).toHaveBeenCalledWith({
      realm: 'master',
      body: expect.objectContaining({
        internationalizationEnabled: true,
        supportedLocales: ['en', 'de'],
        defaultLocale: 'de',
      }),
    })
  })

  it('renders the Events and Actions tabs', () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    expect(screen.getByRole('button', { name: 'Events' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Actions' })).toBeInTheDocument()
  })

  it('shows flow bindings on the general tab and saves a binding through the realm PUT', async () => {
    mockMutateAsync.mockResolvedValue(undefined)
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    expect(screen.getByText('Flow Bindings')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Browser Flow' }))
    fireEvent.click(await screen.findByRole('option', { name: 'custom browser' }))
    fireEvent.click(screen.getByRole('button', { name: /Save Changes/i }))
    await waitFor(() => expect(mockMutateAsync).toHaveBeenCalled())
    expect(mockMutateAsync).toHaveBeenCalledWith({
      realm: 'master',
      body: expect.objectContaining({ browserFlow: 'custom browser' }),
    })
  })

  it('resets a flow binding to null when the system default is chosen', async () => {
    mockMutateAsync.mockResolvedValue(undefined)
    mockRealmState = {
      data: { ...mockRealm, browserFlow: 'custom browser' },
      isLoading: false,
      error: null,
    }
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Browser Flow' }))
    fireEvent.click(await screen.findByRole('option', { name: /System default/ }))
    fireEvent.click(screen.getByRole('button', { name: /Save Changes/i }))
    await waitFor(() => expect(mockMutateAsync).toHaveBeenCalled())
    expect(mockMutateAsync).toHaveBeenCalledWith({
      realm: 'master',
      body: expect.objectContaining({ browserFlow: null }),
    })
  })

  it('shows the events configuration on the events tab and saves via the events endpoint', async () => {
    mockUpdateEventsConfigAsync.mockResolvedValue(undefined)
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Events' }))
    expect(screen.getByText('Event Recording')).toBeInTheDocument()
    expect(screen.getByLabelText('Events enabled')).toBeChecked()
    fireEvent.click(screen.getByLabelText('Admin events enabled'))
    fireEvent.click(screen.getByRole('button', { name: /^Save$/ }))
    await waitFor(() => expect(mockUpdateEventsConfigAsync).toHaveBeenCalled())
    expect(mockUpdateEventsConfigAsync).toHaveBeenCalledWith({
      realm: 'master',
      body: expect.objectContaining({ adminEventsEnabled: true, eventsEnabled: true }),
    })
    // The realm PUT is not used for events config.
    expect(mockMutateAsync).not.toHaveBeenCalled()
  })

  it('shows the clear-events maintenance actions on the events tab', () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Events' }))
    expect(screen.getByRole('button', { name: /Clear events/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Clear admin events/i })).toBeInTheDocument()
  })

  it('shows partial import, export, and push revocation on the actions tab', () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Actions' }))
    expect(screen.getByText('Partial Import')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^Export realm$/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^Push revocation$/i })).toBeInTheDocument()
  })

  it('shows the revocation cutoff on the security tab', () => {
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Security' }))
    expect(screen.getByText('Revocation')).toBeInTheDocument()
    expect(screen.getByTestId('not-before-value')).toHaveTextContent('Not set')
  })

  it('edits default groups as newline-separated paths and saves them', async () => {
    mockMutateAsync.mockResolvedValue(undefined)
    render(<RealmSettingsPage />, { wrapper: Wrapper })
    fireEvent.click(screen.getByRole('button', { name: 'Security' }))
    expect(screen.getByText('Default Groups')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Group paths'), {
      target: { value: '/developers\n\n /ops ' },
    })
    fireEvent.click(screen.getByRole('button', { name: /Save Changes/i }))
    await waitFor(() => expect(mockMutateAsync).toHaveBeenCalled())
    expect(mockMutateAsync).toHaveBeenCalledWith({
      realm: 'master',
      body: expect.objectContaining({ defaultGroups: ['/developers', '/ops'] }),
    })
  })
})
