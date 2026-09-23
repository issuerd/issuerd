// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect } from 'vitest'
import { render } from '@testing-library/react'
import Spinner from './Spinner'

describe('Spinner', () => {
  it('renders with default size', () => {
    const { container } = render(<Spinner />)
    const spinner = container.firstChild as HTMLElement
    expect(spinner).toBeInTheDocument()
    expect(spinner.style.width).toBe('24px')
    expect(spinner.style.height).toBe('24px')
  })

  it('renders with custom size', () => {
    const { container } = render(<Spinner size={48} />)
    const spinner = container.firstChild as HTMLElement
    expect(spinner.style.width).toBe('48px')
    expect(spinner.style.height).toBe('48px')
  })

  it('applies custom className', () => {
    const { container } = render(<Spinner className="my-class" />)
    expect(container.firstChild).toHaveClass('my-class')
  })
})
