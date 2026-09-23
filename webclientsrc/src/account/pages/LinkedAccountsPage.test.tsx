// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import LinkedAccountsPage from './LinkedAccountsPage'

const mockListLinkedAccounts = vi.fn()
const mockLinkIdentity = vi.fn()
const mockUnlinkIdentity = vi.fn()
const mockGetLoginContext = vi.fn()

vi.mock('@generated', () => ({
  accountListLinkedAccounts: (...args: unknown[]) => mockListLinkedAccounts(...args),
  accountLinkIdentity: (...args: unknown[]) => mockLinkIdentity(...args),
  accountUnlinkIdentity: (...args: unknown[]) => mockUnlinkIdentity(...args),
  loginContext: (...args: unknown[]) => mockGetLoginContext(...args),
}))

const linked = {
  alias: 'github',
  provider_id: 'github',
  display_name: 'GitHub',
  external_username: 'octocat',
  display_name: 'GitHub',
  external_username: 'octocat',
  created_at: '2026-02-01T12:00:00Z',
}

const googleIdp = { alias: 'google', display_name: 'Google', provider_id: 'google' }
const githubIdp = { alias: 'github', display_name: 'GitHub', provider_id: 'github' }

const originalLocation = window.location

function setLocation(search: string) {
  Object.defineProperty(window, 'location', {
    configurable: true,
    value: {
      ...originalLocation,
      href: 'http://localhost/realms/master/account/linked-accounts',
      pathname: '/realms/master/account/linked-accounts',
      search,
    },
    writable: true,
  })
}

describe('LinkedAccountsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    setLocation('')
    mockGetLoginContext.mockResolvedValue({
      data: { identity_providers: [] },
      error: undefined,
      response: { status: 200 },
    })
    vi.spyOn(window, 'confirm').mockReturnValue(true)
  })

  afterEach(() => {
    vi.restoreAllMocks()
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: originalLocation,
      writable: true,
    })
  })

  it('shows an empty state when nothing is linked', async () => {
    mockListLinkedAccounts.mockResolvedValue({
      data: [],
      error: undefined,
      response: { status: 200 },
    })
    render(<LinkedAccountsPage />)
    expect(
      await screen.findByText('You have not linked any external accounts yet.')
    ).toBeInTheDocument()
  })

  it('renders a row per linked account', async () => {
    mockListLinkedAccounts.mockResolvedValue({
      data: [linked],
      error: undefined,
      response: { status: 200 },
    })
    render(<LinkedAccountsPage />)
    expect(await screen.findByText('GitHub')).toBeInTheDocument()
    expect(screen.getByText('octocat')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Unlink' })).toBeInTheDocument()
  })

  it('lists only not-yet-linked providers as available to link', async () => {
    mockListLinkedAccounts.mockResolvedValue({
      data: [linked],
      error: undefined,
      response: { status: 200 },
    })
    mockGetLoginContext.mockResolvedValue({
      data: { identity_providers: [googleIdp, githubIdp] },
      error: undefined,
      response: { status: 200 },
    })
    render(<LinkedAccountsPage />)
    expect(await screen.findByText('Available to link')).toBeInTheDocument()
    expect(screen.getByText('Google')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Link' })).toBeInTheDocument()
    // github is already linked — no second Link button for it
    expect(screen.getAllByRole('button', { name: 'Link' })).toHaveLength(1)
  })

  it('redirects to the provider when Link is clicked', async () => {
    mockListLinkedAccounts.mockResolvedValue({ data: [], error: undefined, response: { status: 200 } })
    mockGetLoginContext.mockResolvedValue({
      data: { identity_providers: [googleIdp] },
      error: undefined,
      response: { status: 200 },
    })
    mockLinkIdentity.mockResolvedValue({
      data: { redirect_url: 'https://accounts.google.com/o/oauth2/auth?x=1' },
      error: undefined,
      response: { status: 200 },
    })
    render(<LinkedAccountsPage />)

    fireEvent.click(await screen.findByRole('button', { name: 'Link' }))

    await waitFor(() =>
      expect(mockLinkIdentity).toHaveBeenCalledWith({
        path: { realm: 'master', alias: 'google' },
      })
    )
    expect(window.location.href).toBe('https://accounts.google.com/o/oauth2/auth?x=1')
  })

  it('unlinks an account after confirmation and reloads the list', async () => {
    mockListLinkedAccounts
      .mockResolvedValueOnce({ data: [linked], error: undefined, response: { status: 200 } })
      .mockResolvedValueOnce({ data: [], error: undefined, response: { status: 200 } })
    mockUnlinkIdentity.mockResolvedValue({ data: undefined, error: undefined, response: { status: 204 } })
    render(<LinkedAccountsPage />)

    fireEvent.click(await screen.findByRole('button', { name: 'Unlink' }))

    await waitFor(() =>
      expect(mockUnlinkIdentity).toHaveBeenCalledWith({
        path: { realm: 'master', alias: 'github' },
      })
    )
    expect(
      await screen.findByText('You have not linked any external accounts yet.')
    ).toBeInTheDocument()
  })

  it('does not unlink when the confirmation is cancelled', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(false)
    mockListLinkedAccounts.mockResolvedValue({
      data: [linked],
      error: undefined,
      response: { status: 200 },
    })
    render(<LinkedAccountsPage />)

    fireEvent.click(await screen.findByRole('button', { name: 'Unlink' }))

    expect(mockUnlinkIdentity).not.toHaveBeenCalled()
  })

  it('surfaces the last-sign-in-method error from the server', async () => {
    mockListLinkedAccounts.mockResolvedValue({
      data: [linked],
      error: undefined,
      response: { status: 200 },
    })
    mockUnlinkIdentity.mockResolvedValue({
      error: { error: 'cannot unlink the only sign-in method' },
      response: { status: 400 },
    })
    render(<LinkedAccountsPage />)

    fireEvent.click(await screen.findByRole('button', { name: 'Unlink' }))

    expect(
      await screen.findByText('cannot unlink the only sign-in method')
    ).toBeInTheDocument()
    expect(screen.getByText('octocat')).toBeInTheDocument()
  })

  it('shows a success banner from the linked query param and strips it', async () => {
    setLocation('?linked=github')
    const replaceState = vi.spyOn(window.history, 'replaceState')
    mockListLinkedAccounts.mockResolvedValue({
      data: [linked],
      error: undefined,
      response: { status: 200 },
    })
    render(<LinkedAccountsPage />)

    expect(await screen.findByText('Account linked')).toBeInTheDocument()
    expect(replaceState).toHaveBeenCalledWith({}, '', '/realms/master/account/linked-accounts')
  })

  it.each([
    ['already-linked', 'This provider account is already linked to another user'],
    ['link-session-mismatch', 'Sign-in session mismatch — please try again'],
    ['link-failed', 'Linking failed — please try again'],
  ])('maps the %s query param to an error banner', async (code, message) => {
    setLocation(`?error=${code}`)
    mockListLinkedAccounts.mockResolvedValue({
      data: [],
      error: undefined,
      response: { status: 200 },
    })
    render(<LinkedAccountsPage />)

    expect(await screen.findByText(message)).toBeInTheDocument()
  })
})
