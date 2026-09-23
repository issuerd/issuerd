// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import Footer from './Footer'

describe('Footer', () => {
  it('renders footer text', () => {
    render(<Footer />)
    expect(screen.getByText('Issuerd Admin Console')).toBeInTheDocument()
  })
})
