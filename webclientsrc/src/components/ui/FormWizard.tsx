// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState, type ReactNode } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { cn } from '@/lib/utils'
import { Check, ChevronRight } from 'lucide-react'
import Button from './Button'

export interface WizardStep {
  id: string
  title: string
  description?: string
  content: ReactNode
  validate?: () => boolean | Promise<boolean>
}

interface FormWizardProps {
  steps: WizardStep[]
  onSubmit: () => void | Promise<void>
  onCancel: () => void
  loading?: boolean
  submitLabel?: string
}

export default function FormWizard({
  steps,
  onSubmit,
  onCancel,
  loading,
  submitLabel = 'Create',
}: FormWizardProps) {
  const [current, setCurrent] = useState(0)
  const [validating, setValidating] = useState(false)

  async function goNext() {
    const validate = steps[current].validate
    if (validate) {
      setValidating(true)
      const ok = await validate()
      setValidating(false)
      if (!ok) return
    }
    if (current < steps.length - 1) setCurrent((c) => c + 1)
  }

  function goBack() {
    if (current > 0) setCurrent((c) => c - 1)
  }

  const isLast = current === steps.length - 1

  return (
    <div className="flex flex-col gap-6">
      {/* Step indicator */}
      <div className="flex items-center gap-2">
        {steps.map((step, idx) => {
          const status = idx < current ? 'done' : idx === current ? 'active' : 'pending'
          return (
            <div key={step.id} className="flex items-center gap-2 flex-1">
              <button
                type="button"
                disabled={idx > current}
                onClick={() => idx < current && setCurrent(idx)}
                className={cn(
                  'flex items-center justify-center w-8 h-8 rounded-full text-sm font-semibold transition-colors shrink-0',
                  status === 'done' && 'bg-matrix-green text-obsidian',
                  status === 'active' && 'bg-cyan-neon text-obsidian ring-2 ring-cyan-neon/30',
                  status === 'pending' && 'bg-white/5 text-text-tertiary border border-border-custom'
                )}
              >
                {status === 'done' ? <Check className="w-4 h-4" /> : idx + 1}
              </button>
              <div className="hidden sm:flex flex-col min-w-0">
                <span
                  className={cn(
                    'text-xs font-medium truncate',
                    status === 'active' ? 'text-text-primary' : 'text-text-secondary'
                  )}
                >
                  {step.title}
                </span>
                {step.description && (
                  <span className="text-[10px] text-text-tertiary truncate">{step.description}</span>
                )}
              </div>
              {idx < steps.length - 1 && (
                <ChevronRight className="w-4 h-4 text-text-tertiary shrink-0 ml-auto" />
              )}
            </div>
          )
        })}
      </div>

      {/* Step content */}
      <div className="min-h-[200px]">
        <AnimatePresence mode="wait">
          <motion.div
            key={current}
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -20 }}
            transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
          >
            {steps[current].content}
          </motion.div>
        </AnimatePresence>
      </div>

      {/* Footer */}
      <div className="flex items-center justify-between pt-4 border-t border-border-custom">
        <Button type="button" variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
        <div className="flex items-center gap-3">
          {current > 0 && (
            <Button type="button" variant="ghost" onClick={goBack}>
              Back
            </Button>
          )}
          {isLast ? (
            <Button type="button" loading={loading || validating} onClick={onSubmit}>
              {submitLabel}
            </Button>
          ) : (
            <Button type="button" loading={validating} onClick={goNext}>
              Next
            </Button>
          )}
        </div>
      </div>
    </div>
  )
}
