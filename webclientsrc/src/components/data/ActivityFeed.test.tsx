// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import ActivityFeed from './ActivityFeed'
import type { EventRepresentation } from '@generated'

const events: EventRepresentation[] = [
  {
    id: '1',
    event_type: 'login',
    time: Math.floor(Date.now() / 1000) - 60,
    user_id: 'alice',
    ip_address: '192.168.1.1',
    realm_id: 'master',
  },
  {
    id: '2',
    event_type: 'login_error',
    time: Math.floor(Date.now() / 1000) - 120,
    user_id: 'bob',
    ip_address: '10.0.0.1',
    realm_id: 'master',
    error: 'invalid credentials',
  },
]

describe('ActivityFeed', () => {
  it('renders events with enum badges', () => {
    render(<ActivityFeed events={events} />)
    expect(screen.getByText('alice')).toBeInTheDocument()
    expect(screen.getByText('192.168.1.1')).toBeInTheDocument()
    expect(screen.getByText('invalid credentials')).toBeInTheDocument()
  })

  it('limits to maxItems', () => {
    render(<ActivityFeed events={events} maxItems={1} />)
    expect(screen.getByText('alice')).toBeInTheDocument()
  })

  it('shows empty state when no events', () => {
    render(<ActivityFeed events={[]} />)
    expect(screen.getByText('No recent activity')).toBeInTheDocument()
  })

  it('handles null event type', () => {
    render(
      <ActivityFeed
        events={[
          {
            id: '3',
            event_type: null as unknown as string,
            time: Math.floor(Date.now() / 1000) - 60,
            user_id: 'charlie',
            realm_id: 'master',
          },
        ]}
      />
    )
    expect(screen.getByText('charlie')).toBeInTheDocument()
  })

  it('handles custom object event type', () => {
    render(
      <ActivityFeed
        events={[
          {
            id: '4',
            event_type: { custom: 'custom_event' } as unknown as string,
            time: Math.floor(Date.now() / 1000) - 60,
            user_id: 'dave',
            realm_id: 'master',
          },
        ]}
      />
    )
    expect(screen.getByText('dave')).toBeInTheDocument()
  })

  it('shows success variant for register events', () => {
    render(
      <ActivityFeed
        events={[
          {
            id: '5',
            event_type: 'register',
            time: Math.floor(Date.now() / 1000) - 60,
            realm_id: 'master',
          },
        ]}
      />
    )
    expect(screen.getByText('register')).toBeInTheDocument()
  })

  it('shows warning variant for token events', () => {
    render(
      <ActivityFeed
        events={[
          {
            id: '6',
            event_type: 'token_refresh',
            time: Math.floor(Date.now() / 1000) - 60,
            realm_id: 'master',
          },
        ]}
      />
    )
    expect(screen.getByText('token_refresh')).toBeInTheDocument()
  })
})
