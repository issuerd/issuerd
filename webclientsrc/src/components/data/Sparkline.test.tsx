// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect, vi } from 'vitest'
import { render } from '@testing-library/react'
import Sparkline from './Sparkline'

// ResponsiveContainer requires container dimensions; jsdom has none.
// We mock recharts to keep the test stable.
vi.mock('recharts', () => ({
  ResponsiveContainer: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  AreaChart: ({ children }: { children: React.ReactNode }) => <svg>{children}</svg>,
  Area: () => <path />,
  YAxis: () => null,
}))

describe('Sparkline', () => {
  it('renders an area chart', () => {
    const { container } = render(<Sparkline data={[1, 2, 3, 4, 5]} trend="up" />)
    expect(container.querySelector('svg')).toBeInTheDocument()
  })

  it('renders with neutral trend when unspecified', () => {
    const { container } = render(<Sparkline data={[5, 4, 3, 2, 1]} />)
    expect(container.querySelector('svg')).toBeInTheDocument()
  })
})
