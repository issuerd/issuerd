// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import FlowBindingsSection from './FlowBindingsSection'
import { renderWithProviders } from '../../test/utils'

const mockFlows = [
  { alias: 'browser', top_level: true, built_in: true },
  { alias: 'direct grant', top_level: true, built_in: true },
  { alias: 'custom browser', top_level: true, built_in: false },
  { alias: 'browser sub-flow', top_level: false, built_in: true },
]

vi.mock('../../api/hooks/useAuthFlows', () => ({
  useFlows: () => ({ data: mockFlows, isLoading: false, error: null }),
}))

describe('FlowBindingsSection', () => {
  const onPatch = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders all five binding dropdowns', () => {
    renderWithProviders(
      <FlowBindingsSection realm="master" values={{}} onPatch={onPatch} />
    )
    expect(screen.getByText('Flow Bindings')).toBeInTheDocument()
    for (const label of [
      'Browser Flow',
      'Direct Grant Flow',
      'Reset Credentials Flow',
      'First Broker Login Flow',
      'Registration Flow',
    ]) {
      expect(screen.getByRole('button', { name: label })).toBeInTheDocument()
    }
  })

  it('offers top-level flows plus a system-default empty option', async () => {
    renderWithProviders(
      <FlowBindingsSection realm="master" values={{}} onPatch={onPatch} />
    )
    fireEvent.click(screen.getByRole('button', { name: 'Browser Flow' }))
    expect(await screen.findByRole('option', { name: /System default/ })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'custom browser' })).toBeInTheDocument()
    // Non-top-level flows are not bindable.
    expect(screen.queryByRole('option', { name: 'browser sub-flow' })).not.toBeInTheDocument()
  })

  it('describes the system-default option with the built-in flow name', async () => {
    renderWithProviders(
      <FlowBindingsSection realm="master" values={{}} onPatch={onPatch} />
    )
    fireEvent.click(screen.getByRole('button', { name: 'Browser Flow' }))
    const option = await screen.findByRole('option', { name: /System default/ })
    expect(option).toHaveAttribute('title', 'Uses the built-in "browser" flow')
  })

  it('patches the binding when a flow is selected', async () => {
    renderWithProviders(
      <FlowBindingsSection realm="master" values={{}} onPatch={onPatch} />
    )
    fireEvent.click(screen.getByRole('button', { name: 'Direct Grant Flow' }))
    fireEvent.click(await screen.findByRole('option', { name: 'custom browser' }))
    expect(onPatch).toHaveBeenCalledWith('directGrantFlow', 'custom browser')
  })

  it('patches null when the system default is selected', async () => {
    renderWithProviders(
      <FlowBindingsSection
        realm="master"
        values={{ registrationFlow: 'custom browser' }}
        onPatch={onPatch}
      />
    )
    fireEvent.click(screen.getByRole('button', { name: 'Registration Flow' }))
    fireEvent.click(await screen.findByRole('option', { name: /System default/ }))
    expect(onPatch).toHaveBeenCalledWith('registrationFlow', null)
  })

  it('keeps a stored alias selectable when it no longer resolves to a flow', () => {
    renderWithProviders(
      <FlowBindingsSection
        realm="master"
        values={{ browserFlow: 'deleted-flow' }}
        onPatch={onPatch}
      />
    )
    expect(screen.getByText('deleted-flow (missing)')).toBeInTheDocument()
  })
})
