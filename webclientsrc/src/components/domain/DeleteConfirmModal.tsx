// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import Modal from '../ui/Modal'

interface DeleteConfirmModalProps {
  open: boolean
  onClose: () => void
  onConfirm: () => void
  title?: string
  description?: string
  loading?: boolean
}

export default function DeleteConfirmModal({
  open,
  onClose,
  onConfirm,
  title = 'Confirm Deletion',
  description = 'Are you sure? This action cannot be undone.',
  loading,
}: DeleteConfirmModalProps) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={title}
      footer={
        <div className="flex justify-end gap-3">
          <button
            onClick={onClose}
            disabled={loading}
            className="px-4 py-2.5 border border-border-custom rounded-lg text-sm text-text-primary hover:border-border-hover hover:bg-white/[0.03] transition-all disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={loading}
            className="px-5 py-2.5 bg-alert-red text-white rounded-lg text-sm font-semibold uppercase tracking-wider hover:shadow-glow-red transition-all disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Delete
          </button>
        </div>
      }
    >
      <p className="text-sm text-text-secondary">{description}</p>
    </Modal>
  )
}
