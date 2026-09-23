// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import SkipLinks from './SkipLinks'

describe('SkipLinks', () => {
  it('renders visually hidden skip links', () => {
    render(<SkipLinks />)
    const mainLink = screen.getByText('Skip to main content')
    const navLink = screen.getByText('Skip to sidebar navigation')

    expect(mainLink).toBeInTheDocument()
    expect(navLink).toBeInTheDocument()
    // They should be sr-only by default
    expect(mainLink).toHaveClass('sr-only')
    expect(navLink).toHaveClass('sr-only')
  })

  it('focuses target element when clicked', () => {
    const main = document.createElement('main')
    main.id = 'main-content'
    document.body.appendChild(main)

    render(<SkipLinks />)
    const mainLink = screen.getByText('Skip to main content')

    fireEvent.click(mainLink)
    expect(document.activeElement).toBe(main)
    expect(main).toHaveAttribute('tabindex', '-1')

    // Cleanup
    document.body.removeChild(main)
  })

  it('focuses sidebar nav when clicked', () => {
    const nav = document.createElement('nav')
    nav.id = 'sidebar-nav'
    document.body.appendChild(nav)

    render(<SkipLinks />)
    const navLink = screen.getByText('Skip to sidebar navigation')

    fireEvent.click(navLink)
    expect(document.activeElement).toBe(nav)
    expect(nav).toHaveAttribute('tabindex', '-1')

    // Cleanup
    document.body.removeChild(nav)
  })

  it('does not throw when target element is missing', () => {
    render(<SkipLinks />)
    const mainLink = screen.getByText('Skip to main content')
    expect(() => fireEvent.click(mainLink)).not.toThrow()
  })
})
