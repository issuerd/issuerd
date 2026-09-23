// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect } from 'vitest'
import { useSidebarStore } from './sidebarStore'

describe('sidebarStore', () => {
  beforeEach(() => {
    useSidebarStore.setState({ isCollapsed: false, isMobileOpen: false })
  })

  it('toggles collapse', () => {
    expect(useSidebarStore.getState().isCollapsed).toBe(false)
    useSidebarStore.getState().toggleCollapse()
    expect(useSidebarStore.getState().isCollapsed).toBe(true)
    useSidebarStore.getState().toggleCollapse()
    expect(useSidebarStore.getState().isCollapsed).toBe(false)
  })

  it('toggles mobile', () => {
    expect(useSidebarStore.getState().isMobileOpen).toBe(false)
    useSidebarStore.getState().toggleMobile()
    expect(useSidebarStore.getState().isMobileOpen).toBe(true)
  })

  it('closes mobile', () => {
    useSidebarStore.setState({ isMobileOpen: true })
    useSidebarStore.getState().closeMobile()
    expect(useSidebarStore.getState().isMobileOpen).toBe(false)
  })
})
