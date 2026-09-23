// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { create } from 'zustand'

export type ToastType = 'success' | 'error' | 'warning' | 'info'

export interface ToastItem {
  id: string
  title: string
  message?: string
  type: ToastType
  duration?: number
}

export interface ToastOptions {
  title: string
  message?: string
  type?: ToastType
  duration?: number
}

interface ToastStore {
  toasts: ToastItem[]
  toast: (options: ToastOptions) => void
  dismissToast: (id: string) => void
}

export const useToastStore = create<ToastStore>((set) => ({
  toasts: [],
  toast: (options) => {
    const id = crypto.randomUUID()
    const newToast: ToastItem = {
      id,
      title: options.title,
      message: options.message,
      type: options.type ?? 'info',
      duration: options.duration ?? 4000,
    }
    set((state) => {
      const toasts = [newToast, ...state.toasts].slice(0, 5)
      return { toasts }
    })
    setTimeout(() => {
      set((state) => ({ toasts: state.toasts.filter((t) => t.id !== id) }))
    }, newToast.duration)
  },
  dismissToast: (id) =>
    set((state) => ({ toasts: state.toasts.filter((t) => t.id !== id) })),
}))

export const toast = (options: ToastOptions) => {
  useToastStore.getState().toast(options)
}
