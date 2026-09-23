// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useEffect } from 'react'
import { useSidebarStore } from '@/stores/sidebarStore'

export default function MobileSidebarOverlay() {
  const { isMobileOpen, closeMobile } = useSidebarStore()

  useEffect(() => {
    if (isMobileOpen) {
      document.body.style.overflow = 'hidden'
    } else {
      document.body.style.overflow = ''
    }
    return () => {
      document.body.style.overflow = ''
    }
  }, [isMobileOpen])

  if (!isMobileOpen) return null

  return (
    <div
      className="fixed inset-0 bg-black/50 z-modal-overlay lg:hidden"
      onClick={closeMobile}
    />
  )
}
