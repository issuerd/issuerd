// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import ProtocolMapperEditor from './ProtocolMapperEditor'
import type { ProtocolMapperRepresentation } from '@generated'

vi.mock('../../api/hooks/useServerInfo', () => ({
  useServerInfo: () => ({
    data: {
      mapper_types: [
        { id: 'oidc-usermodel-attribute-mapper', name: 'User Attribute', description: 'Map a user attribute to a token claim' },
        { id: 'oidc-group-membership-mapper', name: 'Group Membership', description: 'Map group memberships to a claim' },
        { id: 'oidc-audience-mapper', name: 'Audience', description: 'Add audiences to the token' },
      ],
    },
    isLoading: false,
  }),
}))

const existingMapper: ProtocolMapperRepresentation = {
  id: 'm1',
  name: 'department',
  protocol: 'openid-connect',
  protocol_mapper: 'oidc-usermodel-attribute-mapper',
  config: {
    'user.attribute': 'department',
    'claim.name': 'department',
    'jsonType.label': 'String',
    'access.token.claim': 'true',
  },
}

function renderEditor(overrides: Partial<Parameters<typeof ProtocolMapperEditor>[0]> = {}) {
  const props = {
    mappers: [existingMapper],
    isLoading: false,
    error: null,
    onCreate: vi.fn().mockResolvedValue(undefined),
    onUpdate: vi.fn().mockResolvedValue(undefined),
    onDelete: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  }
  render(<ProtocolMapperEditor {...props} />)
  return props
}

describe('ProtocolMapperEditor', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('lists mappers with dynamic type badges', () => {
    renderEditor()
    // name cell + claim-name cell both render the value
    expect(screen.getAllByText('department').length).toBeGreaterThan(0)
    // EnumBadge resolves the label from serverInfo.mapper_types
    expect(screen.getByText('User Attribute')).toBeInTheDocument()
  })

  it('shows empty state when there are no mappers', () => {
    renderEditor({ mappers: [] })
    expect(screen.getByText('No mappers configured.')).toBeInTheDocument()
  })

  it('creates a user-attribute mapper with per-type config fields', async () => {
    const props = renderEditor({ mappers: [] })

    fireEvent.click(screen.getByRole('button', { name: /Add Mapper/ }))
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'my-mapper' } })

    // open the mapper-type dropdown and pick User Attribute
    fireEvent.click(screen.getByText('Select mapper type'))
    fireEvent.click(screen.getByRole('option', { name: /User Attribute/ }))

    // per-type fields appear
    expect(screen.getByLabelText('User Attribute')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('User Attribute'), { target: { value: 'department' } })
    fireEvent.change(screen.getByLabelText('Claim Name'), { target: { value: 'department' } })

    // JSON type dropdown
    fireEvent.click(screen.getByText('Select JSON type'))
    fireEvent.click(screen.getByRole('option', { name: 'String' }))

    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(props.onCreate).toHaveBeenCalled())
    const body = props.onCreate.mock.calls[0][0] as ProtocolMapperRepresentation
    expect(body.name).toBe('my-mapper')
    expect(body.protocol).toBe('openid-connect')
    expect(body.protocol_mapper).toBe('oidc-usermodel-attribute-mapper')
    expect(body.config?.['user.attribute']).toBe('department')
    expect(body.config?.['claim.name']).toBe('department')
    expect(body.config?.['jsonType.label']).toBe('String')
    // target switches default to true
    expect(body.config?.['access.token.claim']).toBe('true')
    expect(body.config?.['id.token.claim']).toBe('true')
    expect(body.config?.['userinfo.token.claim']).toBe('true')
    // multivalued defaults to false
    expect(body.config?.['multivalued']).toBe('false')
  })

  it('shows group-membership specific fields', () => {
    renderEditor({ mappers: [] })
    fireEvent.click(screen.getByRole('button', { name: /Add Mapper/ }))
    fireEvent.click(screen.getByText('Select mapper type'))
    fireEvent.click(screen.getByRole('option', { name: /Group Membership/ }))
    expect(screen.getByLabelText('Full Group Path')).toBeInTheDocument()
    expect(screen.queryByLabelText('User Attribute')).not.toBeInTheDocument()
  })

  it('shows audience specific fields', () => {
    renderEditor({ mappers: [] })
    fireEvent.click(screen.getByRole('button', { name: /Add Mapper/ }))
    fireEvent.click(screen.getByText('Select mapper type'))
    fireEvent.click(screen.getByRole('option', { name: /Audience/ }))
    expect(screen.getByLabelText('Included Client Audience')).toBeInTheDocument()
    expect(screen.getByLabelText('Included Custom Audience')).toBeInTheDocument()
  })

  it('edits an existing mapper with prefilled config', async () => {
    const props = renderEditor()
    fireEvent.click(screen.getByRole('button', { name: 'Edit mapper department' }))

    const nameInput = screen.getByLabelText('Name') as HTMLInputElement
    expect(nameInput.value).toBe('department')
    const attrInput = screen.getByLabelText('User Attribute') as HTMLInputElement
    expect(attrInput.value).toBe('department')

    fireEvent.change(attrInput, { target: { value: 'dept' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(props.onUpdate).toHaveBeenCalled())
    const [mapperId, body] = props.onUpdate.mock.calls[0] as [string, ProtocolMapperRepresentation]
    expect(mapperId).toBe('m1')
    expect(body.config?.['user.attribute']).toBe('dept')
    expect(body.config?.['claim.name']).toBe('department')
  })

  it('deletes a mapper after confirmation', async () => {
    const props = renderEditor()
    fireEvent.click(screen.getByRole('button', { name: 'Delete mapper department' }))
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(props.onDelete).toHaveBeenCalledWith('m1'))
  })

  it('save is disabled without a name and type', () => {
    renderEditor({ mappers: [] })
    fireEvent.click(screen.getByRole('button', { name: /Add Mapper/ }))
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
  })

  it('surfaces onCreate errors in the dialog', async () => {
    const props = renderEditor({ mappers: [] })
    props.onCreate.mockRejectedValue(new Error('duplicate mapper name'))
    fireEvent.click(screen.getByRole('button', { name: /Add Mapper/ }))
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'dup' } })
    fireEvent.click(screen.getByText('Select mapper type'))
    fireEvent.click(screen.getByRole('option', { name: /User Attribute/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('duplicate mapper name')).toBeInTheDocument()
  })
})
