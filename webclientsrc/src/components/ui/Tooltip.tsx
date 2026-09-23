"use client"

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import React from 'react'
import { Tooltip as TooltipPrimitive } from 'radix-ui'
import { cn } from '@/lib/utils'

// Shadcn-style primitive exports
function TooltipProvider({
  delayDuration = 0,
  ...props
}: React.ComponentProps<typeof TooltipPrimitive.Provider>) {
  return (
    <TooltipPrimitive.Provider
      data-slot="tooltip-provider"
      delayDuration={delayDuration}
      {...props}
    />
  )
}

function ShadcnTooltip({
  ...props
}: React.ComponentProps<typeof TooltipPrimitive.Root>) {
  return <TooltipPrimitive.Root data-slot="tooltip" {...props} />
}

function TooltipTrigger({
  ...props
}: React.ComponentProps<typeof TooltipPrimitive.Trigger>) {
  return <TooltipPrimitive.Trigger data-slot="tooltip-trigger" {...props} />
}

function TooltipContent({
  className,
  sideOffset = 0,
  children,
  ...props
}: React.ComponentProps<typeof TooltipPrimitive.Content>) {
  return (
    <TooltipPrimitive.Portal>
      <TooltipPrimitive.Content
        data-slot="tooltip-content"
        sideOffset={sideOffset}
        className={cn(
          "z-modal-content w-fit origin-(--radix-tooltip-content-transform-origin) animate-in rounded-md bg-foreground px-3 py-1.5 text-xs text-balance text-background fade-in-0 zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=closed]:zoom-out-95",
          className
        )}
        {...props}
      >
        {children}
        <TooltipPrimitive.Arrow className="z-50 size-2.5 translate-y-[calc(-50%_-_2px)] rotate-45 rounded-[2px] bg-foreground fill-foreground" />
      </TooltipPrimitive.Content>
    </TooltipPrimitive.Portal>
  )
}

export { ShadcnTooltip as Tooltip, TooltipTrigger, TooltipContent, TooltipProvider }

// Legacy Issuerd tooltip wrapper
export type TooltipPlacement = 'top' | 'bottom' | 'left' | 'right'

interface LegacyTooltipProps {
  content: React.ReactNode
  children: React.ReactNode
  placement?: TooltipPlacement
  className?: string
  disabled?: boolean
}

export default function LegacyTooltip({
  content,
  children,
  placement = 'top',
  className,
  disabled = false,
}: LegacyTooltipProps) {
  if (disabled || !content) {
    return <>{children}</>
  }

  return (
    <TooltipProvider delayDuration={0}>
      <ShadcnTooltip>
        <TooltipTrigger asChild>
          <span className="inline">{children}</span>
        </TooltipTrigger>
        <TooltipContent
          side={placement}
          className={cn(
            'max-w-[280px] px-3.5 py-2.5 text-[13px] leading-relaxed',
            className
          )}
        >
          {content}
        </TooltipContent>
      </ShadcnTooltip>
    </TooltipProvider>
  )
}
