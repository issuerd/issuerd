// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, it, expect } from 'vitest'
import { renderHook } from '@testing-library/react'
import { useEnumDescription, useEnumDescriptionMap } from './useEnumDescription'
import type { EnumValueRepresentation } from '@generated'

const enumList: EnumValueRepresentation[] = [
  { id: 'openid-connect', name: 'openid-connect', description: 'OpenID Connect 1.0 protocol' },
  { id: 'saml', name: 'saml', description: 'SAML 2.0 protocol' },
  { id: 'none', name: 'none', description: null },
]

describe('useEnumDescription', () => {
  it('returns the matching enum value by id', () => {
    const { result } = renderHook(() => useEnumDescription(enumList, 'saml'))
    expect(result.current).toEqual({
      id: 'saml',
      name: 'saml',
      description: 'SAML 2.0 protocol',
    })
  })

  it('returns undefined when id is not found', () => {
    const { result } = renderHook(() => useEnumDescription(enumList, 'oauth'))
    expect(result.current).toBeUndefined()
  })

  it('returns undefined when id is null or undefined', () => {
    const { result: r1 } = renderHook(() => useEnumDescription(enumList, null))
    expect(r1.current).toBeUndefined()

    const { result: r2 } = renderHook(() => useEnumDescription(enumList, undefined))
    expect(r2.current).toBeUndefined()
  })

  it('returns undefined when enum list is undefined', () => {
    const { result } = renderHook(() => useEnumDescription(undefined, 'saml'))
    expect(result.current).toBeUndefined()
  })

  it('memoizes the result', () => {
    const { result, rerender } = renderHook(
      ({ list, id }: { list: EnumValueRepresentation[]; id: string }) => useEnumDescription(list, id),
      { initialProps: { list: enumList, id: 'saml' } }
    )
    const first = result.current
    rerender({ list: enumList, id: 'saml' })
    expect(result.current).toBe(first)
  })
})

describe('useEnumDescriptionMap', () => {
  it('builds a map from id to description (falling back to name)', () => {
    const { result } = renderHook(() => useEnumDescriptionMap(enumList))
    expect(result.current.get('openid-connect')).toBe('OpenID Connect 1.0 protocol')
    expect(result.current.get('saml')).toBe('SAML 2.0 protocol')
    expect(result.current.get('none')).toBe('none')
  })

  it('returns an empty map when enum list is undefined', () => {
    const { result } = renderHook(() => useEnumDescriptionMap(undefined))
    expect(result.current.size).toBe(0)
  })

  it('memoizes the map', () => {
    const { result, rerender } = renderHook(
      ({ list }: { list: EnumValueRepresentation[] }) => useEnumDescriptionMap(list),
      { initialProps: { list: enumList } }
    )
    const first = result.current
    rerender({ list: enumList })
    expect(result.current).toBe(first)
  })
})
