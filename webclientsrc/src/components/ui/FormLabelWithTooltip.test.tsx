// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import FormLabelWithTooltip from './FormLabelWithTooltip'

describe('FormLabelWithTooltip', () => {
  it('renders label', () => {
    render(<FormLabelWithTooltip label="Name" htmlFor="name" />)
    expect(screen.getByText('Name')).toBeInTheDocument()
  })

  it('shows required indicator', () => {
    render(<FormLabelWithTooltip label="Name" required />)
    expect(screen.getByText('*')).toBeInTheDocument()
  })

  it('renders tooltip when tooltipText is provided', () => {
    render(<FormLabelWithTooltip label="Name" tooltipText="More info" />)
    expect(screen.getByText('More info')).toBeInTheDocument()
  })

  it('does not render tooltip when tooltipText is null', () => {
    render(<FormLabelWithTooltip label="Name" tooltipText={null} />)
    expect(screen.queryByText('More info')).not.toBeInTheDocument()
  })
})
