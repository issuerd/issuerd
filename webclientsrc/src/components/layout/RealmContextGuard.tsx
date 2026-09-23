// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import React from 'react'
import { Navigate } from 'react-router-dom'
import { useAuthStore } from '../../state/authStore'

export default function RealmContextGuard({ children }: { children: React.ReactNode }) {
  const tokenSet = useAuthStore((s) => s.tokenSet)
  const realm = useAuthStore((s) => s.currentRealm)

  if (!tokenSet?.accessToken) {
    window.location.href = '/login.html'
    return null
  }

  if (!realm) {
    return <Navigate to="/realm-picker" replace />
  }

  return <>{children}</>
}
