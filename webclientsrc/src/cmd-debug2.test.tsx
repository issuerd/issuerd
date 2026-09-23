// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import CommandPalette from './components/interactive/CommandPalette'

describe('CommandPalette debug2', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('test1', () => {
    localStorage.setItem('issuerd-recent-pages', JSON.stringify(['/admin/unknown']))
    render(
      <MemoryRouter>
        <CommandPalette open onClose={() => {}} />
      </MemoryRouter>
    )
    expect(screen.getByText('Recent: /admin/unknown')).toBeInTheDocument()
  })

  it('test2', () => {
    render(
      <MemoryRouter>
        <CommandPalette open onClose={() => {}} />
      </MemoryRouter>
    )
    expect(screen.queryByText('Recent:')).not.toBeInTheDocument()
  })
})
