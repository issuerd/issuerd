// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useSessions } from './useSessions'

export function useLiveSessionCount(realm: string) {
  return useSessions(realm, undefined, { refetchInterval: 30000 })
}
