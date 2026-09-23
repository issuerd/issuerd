// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

interface SpinnerProps {
  size?: number
  className?: string
}

export default function Spinner({ size = 24, className }: SpinnerProps) {
  return (
    <div
      className={`inline-block border-2 border-border-custom border-t-cyan-neon rounded-full animate-spin ${className ?? ''}`}
      style={{ width: size, height: size }}
    />
  )
}
