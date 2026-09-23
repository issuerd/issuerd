// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import Input from '../ui/Input'
import { cn } from '@/lib/utils'

interface KerberosConfigFormProps {
  value: Record<string, string>
  onChange: (value: Record<string, string>) => void
  className?: string
  section?: 'realm' | 'options' | 'all'
}

export default function KerberosConfigForm({ value, onChange, className, section = 'all' }: KerberosConfigFormProps) {
  const setField = (key: string, val: string) => {
    onChange({ ...value, [key]: val })
  }

  const setCheckbox = (key: string, checked: boolean) => {
    onChange({ ...value, [key]: checked ? 'true' : 'false' })
  }

  const showRealm = section === 'all' || section === 'realm'
  const showOptions = section === 'all' || section === 'options'

  return (
    <div className={cn('flex flex-col gap-4', className)}>
      {showRealm && (
        <>
          <div className="text-xs font-semibold uppercase tracking-wider text-text-secondary mb-1">
            Realm
          </div>
          <Input
            label="Kerberos Realm"
            placeholder="EXAMPLE.COM"
            value={value.kerberosRealm ?? ''}
            onChange={(e) => setField('kerberosRealm', e.target.value)}
            required
          />

          <div className="text-xs font-semibold uppercase tracking-wider text-text-secondary mt-2 mb-1">
            Service Principal
          </div>
          <Input
            label="Server Principal"
            placeholder="HTTP/issuerd.example.com@EXAMPLE.COM"
            value={value.serverPrincipal ?? ''}
            onChange={(e) => setField('serverPrincipal', e.target.value)}
          />
          <Input
            label="Keytab Path"
            placeholder="/etc/issuerd.keytab"
            value={value.keyTab ?? ''}
            onChange={(e) => setField('keyTab', e.target.value)}
          />
        </>
      )}

      {showOptions && (
        <>
          <div className="text-xs font-semibold uppercase tracking-wider text-text-secondary mt-2 mb-1">
            Options
          </div>
          <label className="flex items-center gap-2 text-sm text-text-secondary cursor-pointer">
            <input
              type="checkbox"
              checked={value.allowPasswordAuthentication === 'true'}
              onChange={(e) => setCheckbox('allowPasswordAuthentication', e.target.checked)}
              className="w-4 h-4 rounded border-border-custom bg-white/[0.03] text-cyan-neon focus:ring-cyan-neon"
            />
            Allow Password Authentication
          </label>
          <label className="flex items-center gap-2 text-sm text-text-secondary cursor-pointer">
            <input
              type="checkbox"
              checked={(value.allowKerberosAuthentication ?? 'true') === 'true'}
              onChange={(e) => setCheckbox('allowKerberosAuthentication', e.target.checked)}
              className="w-4 h-4 rounded border-border-custom bg-white/[0.03] text-cyan-neon focus:ring-cyan-neon"
            />
            Allow Kerberos Authentication (SPNEGO)
          </label>
          <label className="flex items-center gap-2 text-sm text-text-secondary cursor-pointer">
            <input
              type="checkbox"
              checked={(value.updateProfileFirstLogin ?? 'true') === 'true'}
              onChange={(e) => setCheckbox('updateProfileFirstLogin', e.target.checked)}
              className="w-4 h-4 rounded border-border-custom bg-white/[0.03] text-cyan-neon focus:ring-cyan-neon"
            />
            Update Profile on First Login
          </label>
          <label className="flex items-center gap-2 text-sm text-text-secondary cursor-pointer">
            <input
              type="checkbox"
              checked={value.debug === 'true'}
              onChange={(e) => setCheckbox('debug', e.target.checked)}
              className="w-4 h-4 rounded border-border-custom bg-white/[0.03] text-cyan-neon focus:ring-cyan-neon"
            />
            Debug
          </label>
        </>
      )}
    </div>
  )
}
