// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useCallback } from 'react'

const skipTargets = [
  { id: 'main-content', label: 'Skip to main content' },
  { id: 'sidebar-nav', label: 'Skip to sidebar navigation' },
]

export default function SkipLinks() {
  const handleClick = useCallback((id: string) => {
    const el = document.getElementById(id)
    if (el) {
      el.setAttribute('tabindex', '-1')
      el.focus()
      el.addEventListener('blur', () => el.removeAttribute('tabindex'), { once: true })
    }
  }, [])

  return (
    <div className="fixed top-0 left-0 z-[9999] flex gap-2 p-2">
      {skipTargets.map((target) => (
        <button
          key={target.id}
          onClick={() => handleClick(target.id)}
          className="sr-only focus:not-sr-only focus:static focus:px-4 focus:py-2 focus:bg-cyan-neon focus:text-obsidian focus:rounded-lg focus:font-medium focus:text-sm focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-obsidian focus:ring-cyan-neon"
        >
          {target.label}
        </button>
      ))}
    </div>
  )
}
