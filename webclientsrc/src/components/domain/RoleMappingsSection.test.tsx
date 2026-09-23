// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import RoleMappingsSection, { type RoleMappingsHooks } from './RoleMappingsSection'
import type { RoleRepresentation } from '@generated'

vi.mock('../../api/hooks/useClients', () => ({
  useClients: () => ({
    data: [
      { id: 'c1', client_id: 'backend-api' },
      { id: 'c2', client_id: 'frontend-app' },
    ],
    isLoading: false,
  }),
}))

const realmAssigned: RoleRepresentation[] = [{ id: 'r1', name: 'admin', description: 'Realm admin' }]
const realmAvailable: RoleRepresentation[] = [{ id: 'r2', name: 'user' }]
const clientAssigned: RoleRepresentation[] = [{ id: 'r3', name: 'reader' }]
const clientAvailable: RoleRepresentation[] = [{ id: 'r4', name: 'writer' }]

const addRealmRoles = vi.fn().mockResolvedValue(undefined)
const removeRealmRoles = vi.fn().mockResolvedValue(undefined)
const addClientRoles = vi.fn().mockResolvedValue(undefined)
const removeClientRoles = vi.fn().mockResolvedValue(undefined)

function makeHooks(): RoleMappingsHooks {
  return {
    useAssignedRealmRoles: () => ({ data: realmAssigned, isLoading: false }),
    useAvailableRealmRoles: () => ({ data: realmAvailable, isLoading: false }),
    useAssignedClientRoles: (_realm: string, _id: string, clientId: string) => ({
      data: clientId === 'c1' ? clientAssigned : [],
      isLoading: false,
    }),
    useAvailableClientRoles: (_realm: string, _id: string, clientId: string) => ({
      data: clientId === 'c1' ? clientAvailable : [],
      isLoading: false,
    }),
    useAddRealmRoles: () => ({ mutateAsync: addRealmRoles, isPending: false }),
    useRemoveRealmRoles: () => ({ mutateAsync: removeRealmRoles, isPending: false }),
    useAddClientRoles: () => ({ mutateAsync: addClientRoles, isPending: false }),
    useRemoveClientRoles: () => ({ mutateAsync: removeClientRoles, isPending: false }),
  }
}

describe('RoleMappingsSection', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders assigned and available realm roles', () => {
    render(<RoleMappingsSection realm="master" entityId="u1" hooks={makeHooks()} />)
    expect(screen.getByText('admin')).toBeInTheDocument()
    expect(screen.getByText('user')).toBeInTheDocument()
    expect(screen.getByText('Realm admin')).toBeInTheDocument()
  })

  it('assigns a realm role with its full representation', async () => {
    render(<RoleMappingsSection realm="master" entityId="u1" hooks={makeHooks()} />)
    fireEvent.click(screen.getByText('user'))
    await waitFor(() =>
      expect(addRealmRoles).toHaveBeenCalledWith({
        realm: 'master',
        id: 'u1',
        roles: [{ id: 'r2', name: 'user' }],
      })
    )
  })

  it('removes an assigned realm role', async () => {
    render(<RoleMappingsSection realm="master" entityId="u1" hooks={makeHooks()} />)
    fireEvent.click(screen.getByText('admin'))
    await waitFor(() =>
      expect(removeRealmRoles).toHaveBeenCalledWith({
        realm: 'master',
        id: 'u1',
        roles: [{ id: 'r1', name: 'admin', description: 'Realm admin' }],
      })
    )
  })

  it('shows the info note when provided', () => {
    render(<RoleMappingsSection realm="master" entityId="c1" hooks={makeHooks()} note="Full scope is allowed" />)
    expect(screen.getByText('Full scope is allowed')).toBeInTheDocument()
  })

  it('prompts to select a client before showing client roles', () => {
    render(<RoleMappingsSection realm="master" entityId="u1" hooks={makeHooks()} />)
    expect(screen.getByText('Select a client to manage its role mappings.')).toBeInTheDocument()
  })

  it('manages client roles after picking a client', async () => {
    render(<RoleMappingsSection realm="master" entityId="u1" hooks={makeHooks()} />)

    fireEvent.click(screen.getByText('Select a client'))
    fireEvent.click(screen.getByRole('option', { name: 'backend-api' }))

    expect(screen.getByText('reader')).toBeInTheDocument()
    expect(screen.getByText('writer')).toBeInTheDocument()

    fireEvent.click(screen.getByText('writer'))
    await waitFor(() =>
      expect(addClientRoles).toHaveBeenCalledWith({
        realm: 'master',
        id: 'u1',
        clientId: 'c1',
        roles: [{ id: 'r4', name: 'writer' }],
      })
    )

    fireEvent.click(screen.getByText('reader'))
    await waitFor(() =>
      expect(removeClientRoles).toHaveBeenCalledWith({
        realm: 'master',
        id: 'u1',
        clientId: 'c1',
        roles: [{ id: 'r3', name: 'reader' }],
      })
    )
  })
})
