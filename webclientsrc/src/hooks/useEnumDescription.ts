// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useMemo } from 'react'
import type { EnumValueRepresentation } from '@generated'

export function useEnumDescription(
  enumList: EnumValueRepresentation[] | undefined,
  id: string | null | undefined
): EnumValueRepresentation | undefined {
  return useMemo(
    () => enumList?.find((e) => e.id === id),
    [enumList, id]
  )
}

export function useEnumDescriptionMap(
  enumList: EnumValueRepresentation[] | undefined
): Map<string, string> {
  return useMemo(() => {
    const map = new Map<string, string>()
    enumList?.forEach((e) => map.set(e.id, e.description ?? e.name))
    return map
  }, [enumList])
}
