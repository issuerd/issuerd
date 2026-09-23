// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Globe, LogOut } from 'lucide-react'
import { Logo, LogoMark } from '@/components/ui/Logo'
import { useAuthStore } from '../state/authStore'
import { postLogout } from '../api/client'
import { useRealms } from '../api/hooks/useRealms'
import Spinner from '../components/ui/Spinner'
import EmptyState from '../components/ui/EmptyState'
import ErrorMessage from '../components/ui/ErrorMessage'
import StatusBadge from '@/components/data/StatusBadge'
import PageHeader from '@/components/layout/PageHeader'

export default function RealmPicker() {
  const navigate = useNavigate()
  const tokenSet = useAuthStore((s) => s.tokenSet)
  const setRealm = useAuthStore((s) => s.setRealm)
  const logout = useAuthStore((s) => s.logout)
  const { data: realms, isLoading, error } = useRealms()

  useEffect(() => {
    document.title = 'Issuerd — Select Realm'
    if (!tokenSet?.accessToken) {
      navigate('/', { replace: true })
    }
  }, [tokenSet, navigate])

  function handleSelect(name: string) {
    setRealm(name)
    navigate('/users')
  }

  async function handleLogout() {
    await postLogout()
    logout()
    window.location.href = '/login.html?logged_out=1'
  }

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-obsidian">
        <Spinner />
      </div>
    )
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-obsidian p-4">
        <div className="w-full max-w-md">
          <ErrorMessage message={error.message} />
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-obsidian p-4 lg:p-8">
      <div className="max-w-[1280px] mx-auto">
        <div className="flex items-center justify-center gap-3 mb-8">
          <LogoMark className="w-10 h-10 text-white" />
          <Logo className="h-6 w-auto text-white" />
        </div>

        <PageHeader
          title="Select a Realm"
          icon={Globe}
          actions={
            <button
              onClick={handleLogout}
              className="flex items-center gap-2 px-4 py-2.5 border border-border-custom rounded-lg text-sm text-text-primary hover:border-border-hover hover:bg-white/[0.03] transition-all"
            >
              <LogOut className="w-4 h-4" />
              Logout
            </button>
          }
        />

        {realms && realms.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {realms.map((r) => (
              <button
                key={r.realm}
                className="bg-surface-dark border border-border-custom rounded-xl p-5 hover:border-border-hover transition-all cursor-pointer text-left group"
                onClick={() => handleSelect(r.realm)}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-display text-lg text-white group-hover:text-cyan-neon transition-colors">
                    {r.realm}
                  </span>
                  {r.enabled !== false ? (
                    <StatusBadge status="active" />
                  ) : (
                    <StatusBadge status="inactive" />
                  )}
                </div>
                {r.display_name && (
                  <span className="text-sm text-text-secondary">{r.display_name}</span>
                )}
              </button>
            ))}
          </div>
        ) : (
          <EmptyState
            icon={Globe}
            title="No realms"
            description="There are no realms available."
          />
        )}
      </div>
    </div>
  )
}
