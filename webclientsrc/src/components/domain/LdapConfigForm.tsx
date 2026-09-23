// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useEffect, useMemo } from 'react'
import Input from '../ui/Input'
import FormSelect from '../ui/FormSelect'
import FormSwitch from '../ui/FormSwitch'
import FormLabelWithTooltip from '../ui/FormLabelWithTooltip'
import FormContextLine from '../ui/FormContextLine'
import FormSection from '../ui/FormSection'
import { useServerInfo } from '../../api/hooks/useServerInfo'
import { cn } from '@/lib/utils'

interface LdapConfigFormProps {
  value: Record<string, string>
  onChange: (value: Record<string, string>) => void
  className?: string
  section?: 'connection' | 'mapping' | 'all'
}

const VENDOR_PRESETS: Record<string, Partial<Record<string, string>>> = {
  GENERIC: {
    usernameLdapAttribute: 'uid',
    rdnLdapAttribute: 'uid',
    uuidLdapAttribute: 'entryUUID',
    userObjectClasses: 'inetOrgPerson,organizationalPerson',
  },
  ACTIVE_DIRECTORY: {
    usernameLdapAttribute: 'sAMAccountName',
    rdnLdapAttribute: 'cn',
    uuidLdapAttribute: 'objectGUID',
    userObjectClasses: 'person,organizationalPerson,user',
  },
  SAMBA: {
    usernameLdapAttribute: 'sAMAccountName',
    rdnLdapAttribute: 'cn',
    uuidLdapAttribute: 'objectGUID',
    userObjectClasses: 'person,organizationalPerson,user',
  },
}

/** Per-vendor tested examples shown inline as helper text. */
const VENDOR_EXAMPLES: Record<string, Record<string, string>> = {
  GENERIC: {
    connectionUrl: 'ldap://openldap.example.com:389',
    bindDn: 'cn=admin,dc=example,dc=com',
    baseDn: 'dc=example,dc=com',
    usersDn: 'ou=users,dc=example,dc=com',
    groupsDn: 'ou=groups,dc=example,dc=com',
  },
  ACTIVE_DIRECTORY: {
    connectionUrl: 'ldaps://ad.example.com:636',
    bindDn: 'CN=ldapbind,CN=Users,DC=example,DC=com',
    baseDn: 'DC=example,DC=com',
    usersDn: 'CN=Users,DC=example,DC=com',
    groupsDn: 'OU=Groups,DC=example,DC=com',
  },
  SAMBA: {
    connectionUrl: 'ldap://samba.example.com:389',
    bindDn: 'CN=Administrator,CN=Users,DC=samba,DC=example,DC=com',
    baseDn: 'DC=samba,DC=example,DC=com',
    usersDn: 'CN=Users,DC=samba,DC=example,DC=com',
    groupsDn: 'CN=Users,DC=samba,DC=example,DC=com',
  },
}

export default function LdapConfigForm({ value, onChange, className, section = 'all' }: LdapConfigFormProps) {
  const { data: serverInfo, isLoading: infoLoading } = useServerInfo()

  const vendor = value.vendor ?? 'GENERIC'
  const examples = VENDOR_EXAMPLES[vendor] ?? VENDOR_EXAMPLES.GENERIC

  const vendors = useMemo(
    () =>
      serverInfo?.ldap_vendors.map((v) => ({
        value: v.id,
        label: v.name ?? v.id,
        description: v.description,
      })) ?? [],
    [serverInfo?.ldap_vendors]
  )

  const scopes = useMemo(
    () =>
      serverInfo?.ldap_search_scopes.map((v) => ({
        value: v.id,
        label: v.name ?? v.id,
        description: v.description,
      })) ?? [],
    [serverInfo?.ldap_search_scopes]
  )

  const editModes = useMemo(
    () =>
      serverInfo?.edit_modes.map((v) => ({
        value: v.id,
        label: v.name ?? v.id,
        description: v.description,
      })) ?? [],
    [serverInfo?.edit_modes]
  )

  const setField = (key: string, val: string) => {
    onChange({ ...value, [key]: val })
  }

  const setCheckbox = (key: string, checked: boolean) => {
    onChange({ ...value, [key]: checked ? 'true' : 'false' })
  }

  useEffect(() => {
    const preset = VENDOR_PRESETS[vendor]
    if (!preset) return
    const next = { ...value }
    let changed = false
    for (const [k, v] of Object.entries(preset)) {
      if (v && !next[k]) {
        next[k] = v
        changed = true
      }
    }
    if (changed) onChange(next)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vendor])

  const showConnection = section === 'all' || section === 'connection'
  const showMapping = section === 'all' || section === 'mapping'

  return (
    <div className={cn('flex flex-col gap-4', className)}>
      {/* Vendor quick-reference banner */}
      <div className="bg-cyan-neon/5 border border-cyan-neon/20 rounded-lg p-3 flex items-start gap-3">
        <div className="text-cyan-neon text-lg leading-none mt-0.5">💡</div>
        <div className="text-sm text-text-secondary">
          <span className="font-medium text-text-primary">{vendor === 'GENERIC' ? 'Generic LDAP' : vendor === 'ACTIVE_DIRECTORY' ? 'Active Directory' : 'Samba AD'} quick reference:</span>
          {' '}{examples.connectionUrl} · Bind {examples.bindDn} · Base {examples.baseDn}
        </div>
      </div>

      {showConnection && (
        <>
          <FormSection
            title="Connection"
            description="How Issuerd reaches your LDAP server"
            sectionId="ldap-connection"
            configuredCount={[
              value.connectionUrl,
              value.vendor,
            ].filter(Boolean).length}
            totalCount={2}
          >
            <Input
              label="Connection URL"
              placeholder="ldap://localhost:389"
              value={value.connectionUrl ?? ''}
              onChange={(e) => setField('connectionUrl', e.target.value)}
              required
            />
            <FormContextLine text={`Example: ${examples.connectionUrl}`} />

            <FormSelect
              label="Vendor"
              options={vendors}
              value={vendor}
              onChange={(v) => setField('vendor', v)}
              placeholder={infoLoading ? 'Loading...' : 'Select vendor'}
            />
            <FormContextLine text="Choosing a vendor auto-fills common attribute defaults below." />

            <FormSwitch
              label="Use StartTLS"
              helperText="Encrypt the connection after initial plaintext handshake (port 389). Disable for LDAPS on port 636."
              checked={value.useStartTls === 'true'}
              onChange={(v) => setCheckbox('useStartTls', v)}
            />
          </FormSection>

          <FormSection
            title="Authentication"
            description="Credentials Issuerd uses to bind to the directory"
            sectionId="ldap-auth"
            configuredCount={[
              value.bindDn,
              value.bindCredential,
            ].filter(Boolean).length}
            totalCount={2}
          >
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="flex flex-col gap-1.5">
                <FormLabelWithTooltip
                  label="Bind DN"
                  tooltipText="The distinguished name of the service account Issuerd uses to search the directory."
                />
                <Input
                  placeholder="cn=admin,dc=example,dc=com"
                  value={value.bindDn ?? ''}
                  onChange={(e) => setField('bindDn', e.target.value)}
                />
                <FormContextLine text={`Example: ${examples.bindDn}`} />
              </div>
              <div className="flex flex-col gap-1.5">
                <FormLabelWithTooltip
                  label="Bind Credential"
                  tooltipText="Password for the Bind DN service account."
                />
                <Input
                  type="password"
                  placeholder="Password"
                  value={value.bindCredential ?? ''}
                  onChange={(e) => setField('bindCredential', e.target.value)}
                />
              </div>
            </div>
          </FormSection>

          <FormSection
            title="Directory Structure"
            description="Where users live inside the directory tree"
            sectionId="ldap-dir"
            configuredCount={[
              value.baseDn,
              value.usersDn,
            ].filter(Boolean).length}
            totalCount={2}
          >
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="flex flex-col gap-1.5">
                <FormLabelWithTooltip
                  label="Base DN"
                  tooltipText="Root of the directory tree. All searches start here."
                />
                <Input
                  placeholder="dc=example,dc=com"
                  value={value.baseDn ?? ''}
                  onChange={(e) => setField('baseDn', e.target.value)}
                />
                <FormContextLine text={`Example: ${examples.baseDn}`} />
              </div>
              <div className="flex flex-col gap-1.5">
                <FormLabelWithTooltip
                  label="Users DN"
                  tooltipText="Container where user entries are stored. If empty, Issuerd searches under Base DN."
                />
                <Input
                  placeholder="ou=users,dc=example,dc=com"
                  value={value.usersDn ?? ''}
                  onChange={(e) => setField('usersDn', e.target.value)}
                />
                <FormContextLine text={`Example: ${examples.usersDn}`} />
              </div>
            </div>

            <FormSelect
              label="Search Scope"
              options={scopes}
              value={value.searchScope ?? 'SUBTREE'}
              onChange={(v) => setField('searchScope', v)}
              placeholder={infoLoading ? 'Loading...' : 'Select scope'}
            />
            <FormContextLine text="SUBTREE searches the DN and all descendants. ONELEVEL searches only direct children." />
          </FormSection>
        </>
      )}

      {showMapping && (
        <>
          <FormSection
            title="User Mapping"
            description="Which LDAP attributes map to Issuerd user fields"
            sectionId="ldap-mapping"
            configuredCount={[
              value.usernameLdapAttribute,
              value.rdnLdapAttribute,
              value.uuidLdapAttribute,
              value.userObjectClasses,
            ].filter(Boolean).length}
            totalCount={4}
          >
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="flex flex-col gap-1.5">
                <FormLabelWithTooltip
                  label="Username LDAP Attribute"
                  tooltipText="The LDAP attribute that holds the user's login name (e.g. uid, sAMAccountName)."
                />
                <Input
                  placeholder="uid"
                  value={value.usernameLdapAttribute ?? ''}
                  onChange={(e) => setField('usernameLdapAttribute', e.target.value)}
                />
                <FormContextLine
                  text={
                    vendor === 'ACTIVE_DIRECTORY' || vendor === 'SAMBA'
                      ? 'Example: sAMAccountName'
                      : 'Example: uid'
                  }
                />
              </div>
              <div className="flex flex-col gap-1.5">
                <FormLabelWithTooltip
                  label="RDN LDAP Attribute"
                  tooltipText="Relative Distinguished Name attribute used when creating new LDAP entries."
                />
                <Input
                  placeholder="uid"
                  value={value.rdnLdapAttribute ?? ''}
                  onChange={(e) => setField('rdnLdapAttribute', e.target.value)}
                />
                <FormContextLine
                  text={
                    vendor === 'ACTIVE_DIRECTORY' || vendor === 'SAMBA'
                      ? 'Example: cn'
                      : 'Example: uid'
                  }
                />
              </div>
              <div className="flex flex-col gap-1.5">
                <FormLabelWithTooltip
                  label="UUID LDAP Attribute"
                  tooltipText="Immutable unique identifier attribute. Used to track users across renames."
                />
                <Input
                  placeholder="entryUUID"
                  value={value.uuidLdapAttribute ?? ''}
                  onChange={(e) => setField('uuidLdapAttribute', e.target.value)}
                />
                <FormContextLine
                  text={
                    vendor === 'ACTIVE_DIRECTORY' || vendor === 'SAMBA'
                      ? 'Example: objectGUID'
                      : 'Example: entryUUID'
                  }
                />
              </div>
              <div className="flex flex-col gap-1.5">
                <FormLabelWithTooltip
                  label="User Object Classes"
                  tooltipText="Comma-separated LDAP object classes assigned to new user entries."
                />
                <Input
                  placeholder="inetOrgPerson,organizationalPerson"
                  value={value.userObjectClasses ?? ''}
                  onChange={(e) => setField('userObjectClasses', e.target.value)}
                />
                <FormContextLine
                  text={
                    vendor === 'ACTIVE_DIRECTORY' || vendor === 'SAMBA'
                      ? 'Example: person, organizationalPerson, user'
                      : 'Example: inetOrgPerson, organizationalPerson'
                  }
                />
              </div>
            </div>

            <div className="flex flex-col gap-1.5">
              <FormLabelWithTooltip
                label="Custom User Search Filter"
                tooltipText="Optional LDAP filter expression appended to every user search. Must start with '(' and end with ')'."
              />
              <Input
                placeholder="(employeeType=internal)"
                value={value.customUserSearchFilter ?? ''}
                onChange={(e) => setField('customUserSearchFilter', e.target.value)}
              />
              <FormContextLine text="Example: (&(objectClass=person)(employeeType=internal))" />
            </div>
          </FormSection>

          <FormSection
            title="Group Sync"
            description="Sync directory group memberships into same-named Issuerd groups"
            sectionId="ldap-group-sync"
            configuredCount={[value.groupsDn, value.groupsInclude].filter(Boolean).length}
            totalCount={2}
          >
            <div className="flex flex-col gap-1.5">
              <FormLabelWithTooltip
                label="Groups DN"
                tooltipText="Subtree holding group entries. Memberships are read from the user memberOf DNs under this DN. Leave empty to disable group sync. When set, the synced group set is authoritative: memberships previously imported by sync are removed when the directory no longer reports them."
              />
              <Input
                placeholder="ou=groups,dc=example,dc=com"
                value={value.groupsDn ?? ''}
                onChange={(e) => setField('groupsDn', e.target.value)}
              />
              <FormContextLine text={`Example: ${examples.groupsDn}. Empty = no group sync.`} />
            </div>

            <div className="flex flex-col gap-1.5">
              <FormLabelWithTooltip
                label="Include Groups"
                tooltipText="Optional comma-separated allowlist of group names. Only these groups are synced; everything else in the Groups DN subtree is ignored."
              />
              <Input
                placeholder="developers, ops"
                value={value.groupsInclude ?? ''}
                onChange={(e) => setField('groupsInclude', e.target.value)}
              />
              <FormContextLine text="Comma-separated group CNs. Empty = sync every group found under Groups DN." />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="flex flex-col gap-1.5">
                <FormLabelWithTooltip
                  label="MemberOf LDAP Attribute"
                  tooltipText="User attribute holding the membership DNs (AD/Samba: memberOf; OpenLDAP needs the memberOf overlay). Issuerd requests it explicitly in searches because some directories hide operational attributes from '*'"
                />
                <Input
                  placeholder="memberOf"
                  value={value.memberOfLdapAttribute ?? ''}
                  onChange={(e) => setField('memberOfLdapAttribute', e.target.value)}
                />
                <FormContextLine text="Default: memberOf" />
              </div>
              <div className="flex flex-col gap-1.5">
                <FormLabelWithTooltip
                  label="Group Name LDAP Attribute"
                  tooltipText="Reserved for the (not yet implemented) LoadGroupsByMemberAttribute retrieval strategy. The current memberOf strategy always takes the group name from the first RDN value of the memberOf DN, so this key has no effect today."
                />
                <Input
                  placeholder="cn"
                  value={value.groupNameLdapAttribute ?? ''}
                  onChange={(e) => setField('groupNameLdapAttribute', e.target.value)}
                />
                <FormContextLine text="Default: cn — no effect with the current memberOf strategy." />
              </div>
            </div>
          </FormSection>

          <FormSection
            title="Behaviour"
            description="How Issuerd interacts with the directory"
            sectionId="ldap-behaviour"
            configuredCount={[
              value.editMode,
              value.pagination,
            ].filter(Boolean).length}
            totalCount={2}
          >
            <FormSelect
              label="Edit Mode"
              options={editModes}
              value={value.editMode ?? 'READONLY'}
              onChange={(v) => setField('editMode', v)}
              placeholder={infoLoading ? 'Loading...' : 'Select mode'}
            />
            <FormContextLine text="READONLY = sync only. WRITABLE = two-way sync (password changes write back to LDAP)." />

            <FormSwitch
              label="Enable Pagination"
              helperText="Request results in chunks via Simple Paged Control. Required for directories with >1,000 users."
              checked={value.pagination === 'true'}
              onChange={(v) => setCheckbox('pagination', v)}
            />

            <div className="grid grid-cols-2 gap-4">
              <div className="flex flex-col gap-1.5">
                <FormLabelWithTooltip
                  label="Batch Size"
                  tooltipText="Number of entries requested per page when pagination is enabled."
                />
                <Input
                  type="number"
                  placeholder="1000"
                  value={value.batchSize ?? ''}
                  onChange={(e) => setField('batchSize', e.target.value)}
                />
              </div>
              <div className="flex flex-col gap-1.5">
                <FormLabelWithTooltip
                  label="Max Conditions"
                  tooltipText="Maximum number of LDAP filter conditions sent in a single query."
                />
                <Input
                  type="number"
                  placeholder="1000"
                  value={value.maxConditions ?? ''}
                  onChange={(e) => setField('maxConditions', e.target.value)}
                />
              </div>
            </div>
          </FormSection>
        </>
      )}
    </div>
  )
}
