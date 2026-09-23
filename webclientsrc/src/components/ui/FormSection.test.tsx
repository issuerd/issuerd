// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { render, screen } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import userEvent from '@testing-library/user-event'
import FormSection from './FormSection'

describe('FormSection', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('renders title and description', () => {
    render(
      <FormSection title="Settings" description="Configure options" sectionId="test">
        <div>Content</div>
      </FormSection>
    )
    expect(screen.getByText('Settings')).toBeInTheDocument()
    expect(screen.getByText('Configure options')).toBeInTheDocument()
  })

  it('toggles open/close on click', async () => {
    const user = userEvent.setup()
    render(
      <FormSection title="Settings" sectionId="test">
        <div data-testid="content">Hidden content</div>
      </FormSection>
    )
    expect(screen.getByTestId('content')).toBeInTheDocument()
    await user.click(screen.getByRole('button'))
    // Framer Motion AnimatePresence keeps element in DOM during exit animation
    // Check that the button aria-expanded is false instead
    expect(screen.getByRole('button')).toHaveAttribute('aria-expanded', 'false')
  })

  it('shows badge when collapsed and count provided', async () => {
    const user = userEvent.setup()
    render(
      <FormSection title="Settings" sectionId="test" configuredCount={2} totalCount={5}>
        <div>Content</div>
      </FormSection>
    )
    await user.click(screen.getByRole('button'))
    expect(screen.getByText('2 of 5 configured')).toBeInTheDocument()
  })

  it('persists collapse state to localStorage', async () => {
    const user = userEvent.setup()
    const { unmount } = render(
      <FormSection title="Settings" sectionId="persist-test" defaultOpen={true}>
        <div data-testid="content">Content</div>
      </FormSection>
    )
    await user.click(screen.getByRole('button'))
    unmount()

    render(
      <FormSection title="Settings" sectionId="persist-test" defaultOpen={true}>
        <div data-testid="content2">Content</div>
      </FormSection>
    )
    expect(screen.queryByTestId('content2')).not.toBeInTheDocument()
  })

  it('falls back to defaultOpen when localStorage throws', () => {
    const getItem = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('Storage blocked')
    })
    render(
      <FormSection title="Settings" sectionId="error-test" defaultOpen={false}>
        <div data-testid="content">Content</div>
      </FormSection>
    )
    expect(screen.queryByTestId('content')).not.toBeInTheDocument()
    getItem.mockRestore()
  })
})
