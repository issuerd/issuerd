// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import type {
  UserRepresentation,
  RealmRepresentation,
  ClientRepresentation,
  RoleRepresentation,
  GroupRepresentation,
} from '@generated'

export function makeUser(overrides?: Partial<UserRepresentation>): UserRepresentation {
  return {
    id: 'user-1',
    username: 'alice',
    email: 'alice@example.com',
    first_name: 'Alice',
    last_name: 'Smith',
    enabled: true,
    email_verified: true,
    created_at: new Date().toISOString(),
    ...overrides,
  }
}

export function makeRealm(overrides?: Partial<RealmRepresentation>): RealmRepresentation {
  return {
    realm: 'master',
    display_name: 'Master Realm',
    enabled: true,
    ...overrides,
  }
}

export function makeClient(overrides?: Partial<ClientRepresentation>): ClientRepresentation {
  return {
    id: 'client-1',
    client_id: 'my-app',
    name: 'My Application',
    protocol: 'openid-connect',
    enabled: true,
    public_client: false,
    ...overrides,
  }
}

export function makeRole(overrides?: Partial<RoleRepresentation>): RoleRepresentation {
  return {
    id: 'role-1',
    name: 'admin',
    description: 'Administrator role',
    ...overrides,
  }
}

export function makeGroup(overrides?: Partial<GroupRepresentation>): GroupRepresentation {
  return {
    id: 'group-1',
    name: 'admins',
    path: '/admins',
    ...overrides,
  }
}
