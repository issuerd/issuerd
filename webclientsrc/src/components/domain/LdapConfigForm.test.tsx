// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import LdapConfigForm from './LdapConfigForm'

vi.mock('../../api/hooks/useServerInfo', () => ({
  useServerInfo: () => ({
    data: {
      ldap_vendors: [
        { id: 'GENERIC', name: 'Generic LDAP', description: 'Generic directory' },
        { id: 'ACTIVE_DIRECTORY', name: 'Active Directory', description: 'Microsoft AD' },
        { id: 'SAMBA', name: 'Samba AD', description: 'Samba directory' },
      ],
      ldap_search_scopes: [
        { id: 'SUBTREE', name: 'Subtree', description: 'All descendants' },
        { id: 'ONELEVEL', name: 'One level', description: 'Direct children' },
      ],
      edit_modes: [
        { id: 'READONLY', name: 'Read only', description: 'Synchronize only' },
        { id: 'WRITABLE', name: 'Writable', description: 'Write changes back' },
      ],
    },
    isLoading: false,
  }),
}))

const initialValue = {
  vendor: 'GENERIC',
  usernameLdapAttribute: 'uid',
  rdnLdapAttribute: 'uid',
  uuidLdapAttribute: 'entryUUID',
  userObjectClasses: 'inetOrgPerson,organizationalPerson',
}

describe('LdapConfigForm', () => {
  const onChange = vi.fn()

  beforeEach(() => {
    onChange.mockClear()
  })

  it('applies missing vendor presets', () => {
    render(<LdapConfigForm value={{ vendor: 'ACTIVE_DIRECTORY' }} onChange={onChange} />)

    expect(onChange).toHaveBeenCalledWith({
      vendor: 'ACTIVE_DIRECTORY',
      usernameLdapAttribute: 'sAMAccountName',
      rdnLdapAttribute: 'cn',
      uuidLdapAttribute: 'objectGUID',
      userObjectClasses: 'person,organizationalPerson,user',
    })
  })

  it('emits changes for connection, mapping, group, and behaviour fields', () => {
    render(<LdapConfigForm value={initialValue} onChange={onChange} />)

    fireEvent.change(screen.getByLabelText('Connection URL'), {
      target: { value: 'ldaps://ldap.example.com:636' },
    })
    expect(onChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ connectionUrl: 'ldaps://ldap.example.com:636' }),
    )

    const fields = [
      ['cn=admin,dc=example,dc=com', 'bindDn', 'cn=service,dc=example,dc=com'],
      ['Password', 'bindCredential', 'secret'],
      ['dc=example,dc=com', 'baseDn', 'dc=example,dc=org'],
      ['ou=users,dc=example,dc=com', 'usersDn', 'ou=people,dc=example,dc=org'],
      ['entryUUID', 'uuidLdapAttribute', 'entryUuid'],
      ['inetOrgPerson,organizationalPerson', 'userObjectClasses', 'person'],
      ['(employeeType=internal)', 'customUserSearchFilter', '(employeeType=external)'],
      ['ou=groups,dc=example,dc=com', 'groupsDn', 'ou=teams,dc=example,dc=org'],
      ['developers, ops', 'groupsInclude', 'developers'],
      ['memberOf', 'memberOfLdapAttribute', 'memberOf'],
      ['cn', 'groupNameLdapAttribute', 'cn'],
    ] as const

    for (const [placeholder, key, value] of fields) {
      fireEvent.change(screen.getByPlaceholderText(placeholder), { target: { value } })
      expect(onChange).toHaveBeenLastCalledWith(expect.objectContaining({ [key]: value }))
    }

    const attributeInputs = screen.getAllByPlaceholderText('uid')
    fireEvent.change(attributeInputs[0], { target: { value: 'mail' } })
    expect(onChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ usernameLdapAttribute: 'mail' }),
    )
    fireEvent.change(attributeInputs[1], { target: { value: 'displayName' } })
    expect(onChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ rdnLdapAttribute: 'displayName' }),
    )

    const numberInputs = screen.getAllByPlaceholderText('1000')
    fireEvent.change(numberInputs[0], { target: { value: '500' } })
    expect(onChange).toHaveBeenLastCalledWith(expect.objectContaining({ batchSize: '500' }))
    fireEvent.change(numberInputs[1], { target: { value: '50' } })
    expect(onChange).toHaveBeenLastCalledWith(expect.objectContaining({ maxConditions: '50' }))
  })

  it('emits select and switch changes', () => {
    render(<LdapConfigForm value={initialValue} onChange={onChange} />)

    fireEvent.click(screen.getByLabelText('Vendor'))
    fireEvent.click(screen.getByRole('option', { name: /Active Directory/ }))
    expect(onChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ vendor: 'ACTIVE_DIRECTORY' }),
    )

    fireEvent.click(screen.getByLabelText('Search Scope'))
    fireEvent.click(screen.getByRole('option', { name: /One level/ }))
    expect(onChange).toHaveBeenLastCalledWith(expect.objectContaining({ searchScope: 'ONELEVEL' }))

    fireEvent.click(screen.getByLabelText('Edit Mode'))
    fireEvent.click(screen.getByRole('option', { name: /Writable/ }))
    expect(onChange).toHaveBeenLastCalledWith(expect.objectContaining({ editMode: 'WRITABLE' }))

    fireEvent.click(screen.getByRole('switch', { name: 'Use StartTLS' }))
    expect(onChange).toHaveBeenLastCalledWith(expect.objectContaining({ useStartTls: 'true' }))

    fireEvent.click(screen.getByRole('switch', { name: 'Enable Pagination' }))
    expect(onChange).toHaveBeenLastCalledWith(expect.objectContaining({ pagination: 'true' }))
  })

  it('can render only the connection section', () => {
    render(
      <LdapConfigForm value={initialValue} onChange={onChange} section="connection" />,
    )

    expect(screen.getByText('Connection')).toBeInTheDocument()
    expect(screen.queryByText('User Mapping')).not.toBeInTheDocument()
  })
})
