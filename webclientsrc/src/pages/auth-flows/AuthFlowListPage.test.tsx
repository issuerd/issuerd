// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import AuthFlowListPage from './AuthFlowListPage'

const mockCreate = vi.fn()
const mockCopy = vi.fn()
const mockDelete = vi.fn()
const mockNavigate = vi.fn()

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

vi.mock('../../api/hooks/useAuthFlows', () => ({
  useFlows: () => ({
    data: [
      { alias: 'browser', top_level: true, built_in: true, stages: [{ id: 'e1' }] },
      { alias: 'custom', top_level: true, built_in: false, stages: [] },
      { alias: 'sub flow', top_level: false, built_in: false, stages: [] },
    ],
    isLoading: false,
    error: null,
  }),
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
    </QueryClientProvider>
  )
}

describe('AuthFlowListPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
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
    mockCreate.mockResolvedValue({ alias: 'my-flow' })
    renderPage()

    fireEvent.click(screen.getByRole('button', { name: /Create Flow/ }))
    fireEvent.change(screen.getByLabelText('Alias'), { target: { value: 'my-flow' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(mockCreate).toHaveBeenCalled())
    expect(mockCreate.mock.calls[0][0]).toEqual({ realm: 'master', body: { alias: 'my-flow' } })
  })

  it('copies a flow with a new name', async () => {
    mockCopy.mockResolvedValue({ alias: 'custom v2' })
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
    mockDelete.mockResolvedValue(undefined)
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
})
