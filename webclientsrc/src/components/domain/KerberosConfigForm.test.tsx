// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import KerberosConfigForm from './KerberosConfigForm'

describe('KerberosConfigForm', () => {
  it('emits text and checkbox changes', () => {
    const onChange = vi.fn()
    const value = { kerberosRealm: 'EXAMPLE.COM' }
    render(<KerberosConfigForm value={value} onChange={onChange} />)

    const fields = [
      ['Kerberos Realm', 'kerberosRealm', 'TEST.LOCAL'],
      ['Server Principal', 'serverPrincipal', 'HTTP/idp.test.local@TEST.LOCAL'],
      ['Keytab Path', 'keyTab', '/etc/issuerd/test.keytab'],
    ] as const
    for (const [label, key, nextValue] of fields) {
      fireEvent.change(screen.getByLabelText(label), { target: { value: nextValue } })
      expect(onChange).toHaveBeenLastCalledWith({ ...value, [key]: nextValue })
    }

    const checkboxes = [
      ['Allow Password Authentication', 'allowPasswordAuthentication', 'true'],
      ['Allow Kerberos Authentication (SPNEGO)', 'allowKerberosAuthentication', 'false'],
      ['Update Profile on First Login', 'updateProfileFirstLogin', 'false'],
      ['Debug', 'debug', 'true'],
    ] as const
    for (const [label, key, nextValue] of checkboxes) {
      fireEvent.click(screen.getByLabelText(label))
      expect(onChange).toHaveBeenLastCalledWith({ ...value, [key]: nextValue })
    }
  })

  it('supports rendering only the realm section', () => {
    render(<KerberosConfigForm value={{}} onChange={vi.fn()} section="realm" />)

    expect(screen.getByLabelText('Kerberos Realm')).toBeInTheDocument()
    expect(screen.queryByLabelText('Debug')).not.toBeInTheDocument()
  })
})
