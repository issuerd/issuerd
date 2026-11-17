// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import AuthFlowListPage from './AuthFlowListPage'
import type { FlowRepresentation } from '@generated'

const mockCreate = vi.fn()
const mockCopy = vi.fn()
const mockDelete = vi.fn()
const mockNavigate = vi.fn()

const flows: FlowRepresentation[] = [
  { alias: 'browser', top_level: true, built_in: true, stages: [{ id: 'e1' }] },
  { alias: 'custom', top_level: true, built_in: false, stages: [] },
  { alias: 'sub flow', top_level: false, built_in: false, stages: [] },
]

let mockFlowsState: {
  data: FlowRepresentation[]
  isLoading: boolean
  error: Error | null
} = { data: flows, isLoading: false, error: null }

vi.mock('../../state/authStore', () => ({
  useAuthStore: (selector: (state: { currentRealm: string }) => unknown) =>
    selector({ currentRealm: 'master' }),
}))

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

vi.mock('../../api/hooks/useAuthFlows', () => ({
  useFlows: () => mockFlowsState,
  useCreateFlow: () => ({ mutateAsync: mockCreate, isPending: false }),
  useCopyFlow: () => ({ mutateAsync: mockCopy, isPending: false }),
  useDeleteFlow: () => ({ mutateAsync: mockDelete, isPending: false }),
}))

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <AuthFlowListPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('AuthFlowListPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    window.history.replaceState({}, '', '/')
    mockFlowsState = { data: flows, isLoading: false, error: null }
    mockCreate.mockResolvedValue({ alias: 'my-flow' })
    mockCopy.mockResolvedValue({ alias: 'custom v2' })
    mockDelete.mockResolvedValue(undefined)
  })

  it('lists flows with type and built-in badges', () => {
    renderPage()
    expect(screen.getByText('browser')).toBeInTheDocument()
    expect(screen.getByText('custom')).toBeInTheDocument()
    expect(screen.getByText('Sub Flow')).toBeInTheDocument()
    expect(screen.getAllByText('Top Level').length).toBeGreaterThan(0)
  })

  it('opens the editor on row click', async () => {
    renderPage()
    fireEvent.click(screen.getByText('browser'))
    await waitFor(() =>
      expect(mockNavigate).toHaveBeenCalledWith(`/auth-flows/${encodeURIComponent('browser')}`),
    )
  })

  it('creates a flow via the modal', async () => {
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: /Create Flow/ }))
    fireEvent.change(screen.getByLabelText('Alias'), { target: { value: 'my-flow' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(mockCreate).toHaveBeenCalled())
    expect(mockCreate.mock.calls[0][0]).toEqual({ realm: 'master', body: { alias: 'my-flow' } })
  })

  it('copies a flow with a new name', async () => {
    renderPage()

    fireEvent.click(screen.getByLabelText('Copy flow custom'))
    const input = screen.getByLabelText('New Name')
    fireEvent.change(input, { target: { value: 'custom v2' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(mockCopy).toHaveBeenCalled())
    expect(mockCopy.mock.calls[0][0]).toEqual({
      realm: 'master',
      alias: 'custom',
      body: { newName: 'custom v2' },
    })
  })

  it('deletes a flow after confirmation', async () => {
    renderPage()

    fireEvent.click(screen.getByLabelText('Delete flow custom'))
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }))

    await waitFor(() => expect(mockDelete).toHaveBeenCalled())
    expect(mockDelete.mock.calls[0][0]).toEqual({ realm: 'master', alias: 'custom' })
  })

  it('keeps the delete confirmation open path safe when the server rejects', async () => {
    mockDelete.mockRejectedValue(new Error("flow 'browser' cannot be deleted: bound"))
    renderPage()

    fireEvent.click(screen.getByLabelText('Delete flow browser'))
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }))

    await waitFor(() => expect(mockDelete).toHaveBeenCalled())
  })

  it('shows a loader while flows are loading', () => {
    mockFlowsState = { data: [], isLoading: true, error: null }
    renderPage()

    expect(document.querySelector('.animate-spin')).toBeInTheDocument()
  })

  it('shows the empty state when no flows are configured', () => {
    mockFlowsState = { data: [], isLoading: false, error: null }
    renderPage()

    expect(screen.getByText('No auth flows')).toBeInTheDocument()
    expect(screen.getByText('No authentication flows configured.')).toBeInTheDocument()
  })

  it('shows the query error', () => {
    mockFlowsState = {
      data: [],
      isLoading: false,
      error: new Error('Could not load flows'),
    }
    renderPage()

    expect(screen.getByText('Could not load flows')).toBeInTheDocument()
  })

  it('keeps the create modal open and shows a server error', async () => {
    mockCreate.mockRejectedValueOnce(new Error('Alias already exists'))
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: /Create Flow/ }))
    fireEvent.change(screen.getByLabelText('Alias'), { target: { value: 'browser' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    expect(await screen.findByText('Alias already exists')).toBeInTheDocument()
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })

  it('keeps the copy modal open and shows a server error', async () => {
    mockCopy.mockRejectedValueOnce(new Error('Copy target already exists'))
    renderPage()

    fireEvent.click(screen.getByLabelText('Copy flow custom'))
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    expect(await screen.findByText('Copy target already exists')).toBeInTheDocument()
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })

  it('closes create, copy, and delete modals without mutating flows', async () => {
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: /Create Flow/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())

    fireEvent.click(screen.getByLabelText('Copy flow custom'))
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())

    fireEvent.click(screen.getByLabelText('Delete flow custom'))
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())

    expect(mockCreate).not.toHaveBeenCalled()
    expect(mockCopy).not.toHaveBeenCalled()
    expect(mockDelete).not.toHaveBeenCalled()
  })
})
