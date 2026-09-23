// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect } from 'vitest'
import { render } from '@testing-library/react'
import {
  UsersIllustration,
  ClientsIllustration,
  EventsIllustration,
  SessionsIllustration,
  GenericIllustration,
} from './'

describe('Illustrations', () => {
  it.each([
    { name: 'Users', Component: UsersIllustration },
    { name: 'Clients', Component: ClientsIllustration },
    { name: 'Events', Component: EventsIllustration },
    { name: 'Sessions', Component: SessionsIllustration },
    { name: 'Generic', Component: GenericIllustration },
  ])('$name renders an SVG', ({ Component }) => {
    const { container } = render(<Component />)
    expect(container.querySelector('svg')).toBeInTheDocument()
  })
})
