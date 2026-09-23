// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import CommandPalette from './components/interactive/CommandPalette'

describe('CommandPalette debug', () => {
  it('debug', () => {
    localStorage.setItem('issuerd-recent-pages', JSON.stringify(['/admin/unknown']))
    render(
      <MemoryRouter>
        <CommandPalette open onClose={() => {}} />
      </MemoryRouter>
    )
    screen.debug(undefined, 100000)
  })
})
