// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState } from 'react'
import { Copy, Check } from 'lucide-react'
import { toast } from '@/stores/toastStore'

interface CopyButtonProps {
  text: string
  size?: number
}

export default function CopyButton({ text, size = 14 }: CopyButtonProps) {
  const [isCopied, setIsCopied] = useState(false)

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(text)
      setIsCopied(true)
      toast({ title: 'Copied to clipboard', type: 'success' })
      setTimeout(() => setIsCopied(false), 2000)
    } catch {
      toast({ title: 'Failed to copy', type: 'error' })
    }
  }

  return (
    <button
      onClick={handleCopy}
      className="p-1 hover:bg-white/5 rounded transition-colors text-text-tertiary hover:text-cyan-neon"
      aria-label={isCopied ? 'Copied' : 'Copy to clipboard'}
    >
      {isCopied ? (
        <Check className="text-matrix-green" style={{ width: size, height: size }} aria-hidden="true" />
      ) : (
        <Copy style={{ width: size, height: size }} aria-hidden="true" />
      )}
    </button>
  )
}
