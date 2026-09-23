// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState } from 'react'
import Modal from '../ui/Modal'
import CopyButton from '@/components/data/CopyButton'

interface SecretRevealModalProps {
  open: boolean
  onClose: () => void
  secret: string
}

export default function SecretRevealModal({ open, onClose, secret }: SecretRevealModalProps) {
  const [revealed, setRevealed] = useState(false)

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Client Secret"
      footer={
        <div className="flex justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2.5 border border-border-custom rounded-lg text-sm text-text-primary hover:border-border-hover hover:bg-white/[0.03] transition-all"
          >
            Close
          </button>
        </div>
      }
    >
      <div className="flex flex-col gap-3">
        {!revealed ? (
          <button
            onClick={() => setRevealed(true)}
            className="px-5 py-2.5 bg-cyan-neon text-obsidian rounded-lg text-sm font-semibold uppercase tracking-wider hover:shadow-glow-cyan transition-all"
          >
            Reveal Secret
          </button>
        ) : (
          <>
            <div className="flex items-center gap-2 bg-surface-dark border border-border-custom rounded-lg p-3">
              <code className="flex-1 text-sm font-mono text-white break-all">{secret}</code>
              <CopyButton text={secret} />
            </div>
            <p className="text-xs text-amber">Store this secret safely. It may not be shown again.</p>
          </>
        )}
      </div>
    </Modal>
  )
}
