// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import EnumTooltip from './EnumTooltip'

describe('EnumTooltip', () => {
  it('renders children when no match', () => {
    render(
      <EnumTooltip enumList={[]} value="x" fallback="">
        <span data-testid="child">Child</span>
      </EnumTooltip>
    )
    expect(screen.getByTestId('child')).toBeInTheDocument()
  })

  it('renders tooltip when description matches', () => {
    render(
      <EnumTooltip enumList={[{ id: 'a', name: 'A', description: 'Desc A' }]} value="a">
        <span data-testid="child">Child</span>
      </EnumTooltip>
    )
    expect(screen.getByTestId('child')).toBeInTheDocument()
  })

  it('uses fallback when no enum match', () => {
    render(
      <EnumTooltip enumList={[{ id: 'a', name: 'A', description: 'Desc A' }]} value="b" fallback="Fallback">
        <span data-testid="child">Child</span>
      </EnumTooltip>
    )
    expect(screen.getByTestId('child')).toBeInTheDocument()
  })
})
