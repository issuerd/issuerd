// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import AuthFlowDetailPage from './AuthFlowDetailPage'

const mockCopy = vi.fn()
const mockAddExecution = vi.fn()
const mockAddSubFlow = vi.fn()
const mockUpdateExecution = vi.fn()
const mockDeleteExecution = vi.fn()
const mockCreateConfig = vi.fn()
const mockUpdateConfig = vi.fn()
const mockDeleteConfig = vi.fn()
const mockExecutionConfig = vi.fn()

const editableFlow = {
  alias: 'browser',
  top_level: true,
  built_in: false,
  stages: [
    {
      id: 'e1',
      authenticator: 'auth-cookie',
      requirement: 'alternative',
      priority: 10,
      authenticator_config: { alias: 'cookie cfg', config: { k: 'v' } },
      has_config: true,
    },
    {
      id: 'e2',
      authenticator: 'auth-username-password-form',
      requirement: 'required',
      priority: 20,
      authenticator_config: null,
      has_config: false,
    },
    {
      id: 'e3',
      authenticator: 'forms-subflow',
      requirement: 'alternative',
      priority: 30,
      authenticator_config: null,
      has_config: false,
      sub_flow_alias: 'forms',
    },
  ],
}

let mockFlow: any = editableFlow

vi.mock('../../state/authStore', () => ({
  useAuthStore: (selector: any) => selector({ currentRealm: 'master' }),
}))

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom')
  return {
    ...actual,
    useParams: () => ({ alias: 'browser' }),
  }
})

vi.mock('../../api/hooks/useAuthFlows', () => ({
  useFlow: () => ({ data: mockFlow, isLoading: false, error: null }),
  useCopyFlow: () => ({ mutateAsync: mockCopy, isPending: false }),
  useAddExecution: () => ({ mutateAsync: mockAddExecution, isPending: false }),
  useAddFlowExecution: () => ({ mutateAsync: mockAddSubFlow, isPending: false }),
  useUpdateExecution: () => ({ mutateAsync: mockUpdateExecution, isPending: false }),
  useDeleteExecution: () => ({ mutateAsync: mockDeleteExecution, isPending: false }),
  useExecutionConfig: (realm: string, executionId: string, enabled?: boolean) => {
    mockExecutionConfig(realm, executionId, enabled)
    return {
      data: executionId === 'e1' ? { alias: 'cookie cfg', config: { k: 'v' } } : null,
      isLoading: false,
      isFetching: false,
    }
  },
  useCreateExecutionConfig: () => ({ mutateAsync: mockCreateConfig, isPending: false }),
  useUpdateExecutionConfig: () => ({ mutateAsync: mockUpdateConfig, isPending: false }),
  useDeleteExecutionConfig: () => ({ mutateAsync: mockDeleteConfig, isPending: false }),
}))

vi.mock('../../api/hooks/useServerInfo', () => ({
  useServerInfo: () => ({
    data: {
      requirements: [
        { id: 'required', name: 'Required', description: 'The stage is always executed' },
        { id: 'alternative', name: 'Alternative', description: 'One of the alternatives must succeed' },
        { id: 'optional', name: 'Optional', description: 'Executed when configured' },
        { id: 'disabled', name: 'Disabled', description: 'Never executed' },
        { id: 'conditional', name: 'Conditional', description: 'Evaluated conditionally' },
      ],
      authenticators: [
        { id: 'auth-cookie', name: 'Cookie', description: 'SSO cookie authenticator' },
        { id: 'auth-username-password-form', name: 'Username Password Form', description: 'Username and password form' },
        { id: 'auth-otp-form', name: 'OTP Form', description: 'One-time code form' },
      ],
    },
    isLoading: false,
  }),
}))

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <AuthFlowDetailPage />
      </MemoryRouter>
    </QueryClientProvider>
  )
}

describe('AuthFlowDetailPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockFlow = editableFlow
  })

  it('renders the execution table with provider names and sub-flow indicator', () => {
    renderPage()
    expect(screen.getByText('Cookie')).toBeInTheDocument()
    expect(screen.getByText('Username Password Form')).toBeInTheDocument()
    expect(screen.getByText('forms')).toBeInTheDocument()
    expect(screen.getByText('Configured')).toBeInTheDocument()
    expect(screen.getByText('Top Level')).toBeInTheDocument()
  })

  it('submits an UpdateExecutionRequest-shaped body on requirement change', async () => {
    mockUpdateExecution.mockResolvedValue(undefined)
    renderPage()

    fireEvent.change(screen.getByLabelText('Requirement for auth-username-password-form'), {
      target: { value: 'disabled' },
    })

    await waitFor(() => expect(mockUpdateExecution).toHaveBeenCalled())
    expect(mockUpdateExecution.mock.calls[0][0]).toEqual({
      realm: 'master',
      flowAlias: 'browser',
      body: { id: 'e2', requirement: 'disabled' },
    })
  })

  it('adds an execution with a provider picked from the dynamic dropdown', async () => {
    mockAddExecution.mockResolvedValue({ id: 'e4' })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: /Add Execution/ }))
    const dialog = screen.getByRole('dialog')
    fireEvent.click(within(dialog).getByLabelText('Provider'))
    // FormSelect listboxes are portaled out of the dialog (z-order fix), so
    // scope option queries to the open listbox instead of the dialog.
    const providerListbox = screen.getByRole('listbox')
    // Enum descriptions are surfaced as option subtitles.
    expect(within(providerListbox).getByText('One-time code form')).toBeInTheDocument()
    fireEvent.click(within(providerListbox).getByRole('option', { name: /OTP Form/ }))
    fireEvent.click(within(dialog).getByLabelText('Requirement'))
    fireEvent.click(
      within(screen.getByRole('listbox')).getByRole('option', { name: /^Required/ })
    )
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(mockAddExecution).toHaveBeenCalled())
    expect(mockAddExecution.mock.calls[0][0]).toEqual({
      realm: 'master',
      flowAlias: 'browser',
      body: { provider: 'auth-otp-form', requirement: 'required' },
    })
  })

  it('adds a sub-flow with alias and requirement', async () => {
    mockAddSubFlow.mockResolvedValue({ id: 'e5' })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: /Add Sub-Flow/ }))
    const dialog = screen.getByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('Alias'), { target: { value: 'my sub' } })
    fireEvent.click(within(dialog).getByLabelText('Requirement'))
    fireEvent.click(
      within(screen.getByRole('listbox')).getByRole('option', { name: /^Conditional/ })
    )
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(mockAddSubFlow).toHaveBeenCalled())
    expect(mockAddSubFlow.mock.calls[0][0]).toEqual({
      realm: 'master',
      flowAlias: 'browser',
      body: { alias: 'my sub', requirement: 'conditional' },
    })
  })

  it('deletes an execution after confirmation', async () => {
    mockDeleteExecution.mockResolvedValue(undefined)
    renderPage()

    fireEvent.click(screen.getByLabelText('Delete execution auth-cookie'))
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }))

    await waitFor(() => expect(mockDeleteExecution).toHaveBeenCalled())
    expect(mockDeleteExecution.mock.calls[0][0]).toEqual({ realm: 'master', executionId: 'e1' })
  })

  it('creates a config for a stage without one (POST path)', async () => {
    mockCreateConfig.mockResolvedValue({ alias: 'my cfg' })
    renderPage()

    fireEvent.click(screen.getByLabelText('Configure auth-username-password-form'))
    await waitFor(() => expect(screen.getByLabelText('Alias')).toBeInTheDocument())

    fireEvent.change(screen.getByLabelText('Alias'), { target: { value: 'my cfg' } })
    fireEvent.click(screen.getByRole('button', { name: /Add Row/ }))
    fireEvent.change(screen.getByLabelText('Config key 1'), { target: { value: 'kc' } })
    fireEvent.change(screen.getByLabelText('Config value 1'), { target: { value: 'vc' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(mockCreateConfig).toHaveBeenCalled())
    expect(mockCreateConfig.mock.calls[0][0]).toEqual({
      realm: 'master',
      executionId: 'e2',
      body: { alias: 'my cfg', config: { kc: 'vc' } },
    })
  })

  it('updates an existing config prefilled from the GET (PUT path)', async () => {
    mockUpdateConfig.mockResolvedValue(undefined)
    renderPage()

    fireEvent.click(screen.getByLabelText('Configure auth-cookie'))
    await waitFor(() => expect(screen.getByLabelText('Alias')).toBeInTheDocument())

    // Prefilled from the fetched config.
    expect(screen.getByLabelText('Alias')).toHaveValue('cookie cfg')
    expect(screen.getByLabelText('Config key 1')).toHaveValue('k')
    expect(screen.getByLabelText('Config value 1')).toHaveValue('v')

    fireEvent.change(screen.getByLabelText('Config value 1'), { target: { value: 'v2' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(mockUpdateConfig).toHaveBeenCalled())
    expect(mockUpdateConfig.mock.calls[0][0]).toEqual({
      realm: 'master',
      executionId: 'e1',
      body: { alias: 'cookie cfg', config: { k: 'v2' } },
    })
  })

  it('probes the config endpoint only for stages advertising has_config', async () => {
    renderPage()

    fireEvent.click(screen.getByLabelText('Configure auth-cookie'))
    await waitFor(() => expect(screen.getByLabelText('Alias')).toBeInTheDocument())
    expect(mockExecutionConfig).toHaveBeenCalledWith('master', 'e1', true)

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByLabelText('Alias')).not.toBeInTheDocument())
    mockExecutionConfig.mockClear()

    fireEvent.click(screen.getByLabelText('Configure auth-username-password-form'))
    await waitFor(() => expect(screen.getByLabelText('Alias')).toBeInTheDocument())
    expect(mockExecutionConfig).toHaveBeenCalledWith('master', 'e2', false)
  })

  it('deletes an existing config (DELETE path)', async () => {
    mockDeleteConfig.mockResolvedValue(undefined)
    renderPage()

    fireEvent.click(screen.getByLabelText('Configure auth-cookie'))
    await waitFor(() => expect(screen.getByLabelText('Alias')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Delete Config' }))

    await waitFor(() => expect(mockDeleteConfig).toHaveBeenCalled())
    expect(mockDeleteConfig.mock.calls[0][0]).toEqual({ realm: 'master', executionId: 'e1' })
  })

  it('shows a read-only banner and disables mutations for built-in flows', () => {
    mockFlow = { ...editableFlow, built_in: true }
    renderPage()

    expect(screen.getByText(/built-in flow and cannot be modified/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Add Execution/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Add Sub-Flow/ })).not.toBeInTheDocument()
    expect(screen.queryByLabelText('Delete execution auth-cookie')).not.toBeInTheDocument()
    expect(screen.getByLabelText('Requirement for auth-cookie')).toBeDisabled()
    // Copy stays available for built-in flows.
    expect(screen.getByRole('button', { name: /Copy/ })).toBeInTheDocument()
  })

  it('copies a built-in flow from the detail page', async () => {
    mockFlow = { ...editableFlow, built_in: true }
    mockCopy.mockResolvedValue({ alias: 'browser v2' })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: /Copy/ }))
    fireEvent.change(screen.getByLabelText('New Name'), { target: { value: 'browser v2' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(mockCopy).toHaveBeenCalled())
    expect(mockCopy.mock.calls[0][0]).toEqual({
      realm: 'master',
      alias: 'browser',
      body: { newName: 'browser v2' },
    })
  })
})
