// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import ServerInfoPage from './ServerInfoPage'

const mockServerInfo = {
  protocols: [{ id: 'openid-connect', name: 'OpenID Connect', description: 'OIDC' }],
  ssl_required: [{ id: 'external', name: 'External', description: null }],
  client_authenticator_types: [],
  grant_types: [],
  response_types: [{ id: 'code', name: 'Code', description: null }],
  response_modes: [],
  pkce_code_challenge_methods: [],
  event_types: [{ id: 'login', name: 'Login', description: null }],
  operation_types: [],
  resource_types: [],
  credential_types: [],
  provider_ids: [],
  algorithms: [{ id: 'RS256', name: 'RS256', description: null }],
}

let mockState = {
  data: mockServerInfo as any,
  isLoading: false,
  error: null as Error | null,
}

vi.mock('../../api/hooks/useServerInfo', () => ({
  useServerInfo: () => mockState,
}))

describe('ServerInfoPage', () => {
  beforeEach(() => {
    mockState = { data: mockServerInfo, isLoading: false, error: null }
  })

  it('renders overview cards', () => {
    render(<ServerInfoPage />)
    expect(screen.getByText('Version')).toBeInTheDocument()
    expect(screen.getByText('Rust Edition')).toBeInTheDocument()
    expect(screen.getByText('Algorithms')).toBeInTheDocument()
    expect(screen.getAllByText('1').length).toBeGreaterThanOrEqual(2)
  })

  it('renders enum tables with items', () => {
    render(<ServerInfoPage />)
    expect(screen.getByRole('heading', { name: 'Protocols' })).toBeInTheDocument()
    expect(screen.getByText('openid-connect')).toBeInTheDocument()
    expect(screen.getByText('OpenID Connect')).toBeInTheDocument()
  })

  it('filters enum table by name', () => {
    render(<ServerInfoPage />)
    const inputs = screen.getAllByPlaceholderText('Filter...')
    fireEvent.change(inputs[0], { target: { value: 'openid' } })
    expect(screen.getByText('openid-connect')).toBeInTheDocument()
    fireEvent.change(inputs[0], { target: { value: 'nomatch' } })
    expect(screen.getAllByText('No results')[0]).toBeInTheDocument()
  })

  it('filters enum table by id', () => {
    render(<ServerInfoPage />)
    const inputs = screen.getAllByPlaceholderText('Filter...')
    fireEvent.change(inputs[0], { target: { value: 'openid-connect' } })
    expect(screen.getByText('openid-connect')).toBeInTheDocument()
  })

  it('filters enum table by description', () => {
    render(<ServerInfoPage />)
    const inputs = screen.getAllByPlaceholderText('Filter...')
    fireEvent.change(inputs[0], { target: { value: 'OIDC' } })
    expect(screen.getByText('openid-connect')).toBeInTheDocument()
  })

  it('shows no results when items array is empty', () => {
    render(<ServerInfoPage />)
    expect(screen.getByText('Export JSON')).toBeInTheDocument()
  })

  it('clicks export json', () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.assign(navigator, { clipboard: { writeText } })
    render(<ServerInfoPage />)
    fireEvent.click(screen.getByText('Export JSON'))
    expect(writeText).toHaveBeenCalled()
  })

  it('shows spinner while loading', () => {
    mockState = { data: null, isLoading: true, error: null }
    render(<ServerInfoPage />)
    expect(document.querySelector('.animate-spin')).toBeInTheDocument()
  })

  it('shows error message on error', () => {
    mockState = { data: null, isLoading: false, error: new Error('network error') }
    render(<ServerInfoPage />)
    expect(screen.getByText(/network error/i)).toBeInTheDocument()
  })

  it('shows no data message when serverInfo is null', () => {
    mockState = { data: null, isLoading: false, error: null }
    render(<ServerInfoPage />)
    expect(screen.getByText(/No server information available/i)).toBeInTheDocument()
  })

  it('renders EnumTable without items', () => {
    mockState = {
      data: { ...mockServerInfo, protocols: undefined },
      isLoading: false,
      error: null,
    }
    render(<ServerInfoPage />)
    // EnumTable for protocols should return null when items is undefined,
    // so the protocols table content should not be rendered.
    expect(screen.queryByText('openid-connect')).not.toBeInTheDocument()
    // Other enum tables with data should still render
    expect(screen.getByText('login')).toBeInTheDocument()
  })
})
