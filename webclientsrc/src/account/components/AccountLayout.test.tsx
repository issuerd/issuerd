// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import AccountLayout from './AccountLayout'

vi.mock('../../api/client', () => ({
  postLogout: vi.fn().mockResolvedValue(undefined),
}))

function renderAccount() {
  return render(
    <MemoryRouter initialEntries={['/profile']}>
      <Routes>
        <Route element={<AccountLayout />}>
          <Route path="profile" element={<h1>Personal Info</h1>} />
          <Route path="security" element={<h1>Security</h1>} />
        </Route>
      </Routes>
    </MemoryRouter>,
  )
}

describe('AccountLayout mobile navigation', () => {
  it('opens the account drawer and closes it after navigation', async () => {
    renderAccount()
    const trigger = screen.getByRole('button', { name: 'Open account navigation' })
    expect(trigger).toHaveAttribute('aria-expanded', 'false')

    fireEvent.click(trigger)
    const dialog = await screen.findByRole('dialog', { name: 'Account' })
    expect(trigger).toHaveAttribute('aria-expanded', 'true')

    fireEvent.click(within(dialog).getByRole('link', { name: 'Security', exact: true }))

    expect(await screen.findByRole('heading', { name: 'Security', exact: true })).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(trigger).toHaveAttribute('aria-expanded', 'false')
  })

  it('dismisses the account drawer with Escape', async () => {
    renderAccount()
    fireEvent.click(screen.getByRole('button', { name: 'Open account navigation' }))
    expect(await screen.findByRole('dialog', { name: 'Account' })).toBeInTheDocument()

    fireEvent.keyDown(document, { key: 'Escape' })

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  })
})
