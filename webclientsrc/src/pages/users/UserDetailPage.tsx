// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState, useMemo, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { Users, Pencil, Trash2, KeyRound, Mail, ArrowUp, ArrowDown, Check, X } from 'lucide-react'
import { useAuthStore } from '../../state/authStore'
import {
  useUser,
  useUpdateUser,
  useDeleteUser,
  useResetPassword,
  useUserSessions,
  useUserGroups,
  useUserRealmRoles,
  useAvailableUserRealmRoles,
  useUserClientRoles,
  useAvailableUserClientRoles,
  useAddUserGroup,
  useRemoveUserGroup,
  useAddUserRealmRoles,
  useRemoveUserRealmRoles,
  useAddUserClientRoles,
  useRemoveUserClientRoles,
} from '../../api/hooks/useUsers'
import {
  useUserCredentials,
  useUpdateCredentialLabel,
  useDeleteCredential,
  useMoveCredential,
} from '../../api/hooks/useCredentials'
import { useImpersonateUser, useExecuteActionsEmail } from '../../api/hooks/useUserActions'
import { useGroups } from '../../api/hooks/useGroups'
import { useDeleteSession } from '../../api/hooks/useSessions'
import { useServerInfo } from '../../api/hooks/useServerInfo'
import Spinner from '../../components/ui/Spinner'
import PageLoader from '../../components/ui/PageLoader'
import ErrorMessage from '../../components/ui/ErrorMessage'
import Modal from '../../components/ui/Modal'
import UserForm from '../../components/domain/UserForm'
import DeleteConfirmModal from '../../components/domain/DeleteConfirmModal'
import TwoColumnPicker from '../../components/domain/TwoColumnPicker'
import RoleMappingsSection, { type RoleMappingsHooks } from '../../components/domain/RoleMappingsSection'
import PageHeader from '@/components/layout/PageHeader'
import Badge from '../../components/ui/Badge'
import CopyButton from '@/components/data/CopyButton'
import type {
  UserRepresentation,
  CredentialRepresentation,
  CredentialType,
  EnumValueRepresentation,
} from '@generated'

function credentialTypeToString(ct: CredentialType | null | undefined): string {
  if (!ct) return ''
  if (typeof ct === 'string') return ct
  return ct.custom
}

const tabs = ['Details', 'Credentials', 'Role Mappings', 'Groups', 'Sessions'] as const

const userRoleMappingHooks: RoleMappingsHooks = {
  useAssignedRealmRoles: useUserRealmRoles,
  useAvailableRealmRoles: useAvailableUserRealmRoles,
  useAssignedClientRoles: useUserClientRoles,
  useAvailableClientRoles: useAvailableUserClientRoles,
  useAddRealmRoles: useAddUserRealmRoles,
  useRemoveRealmRoles: useRemoveUserRealmRoles,
  useAddClientRoles: useAddUserClientRoles,
  useRemoveClientRoles: useRemoveUserClientRoles,
}

export default function UserDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const realm = useAuthStore((s) => s.currentRealm)!
  const [activeTab, setActiveTab] = useState<(typeof tabs)[number]>('Details')
  const [showEdit, setShowEdit] = useState(false)
  const [showResetPassword, setShowResetPassword] = useState(false)
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [impersonateOpen, setImpersonateOpen] = useState(false)
  const [actionsEmailOpen, setActionsEmailOpen] = useState(false)

  const { data: user, isLoading, error } = useUser(realm, id!)
  const update = useUpdateUser()
  const remove = useDeleteUser()
  const resetPassword = useResetPassword()
  const impersonate = useImpersonateUser()
  const executeActionsEmail = useExecuteActionsEmail()

  async function handleUpdate(data: UserRepresentation) {
    await update.mutateAsync({ realm, id: id!, body: data })
    setShowEdit(false)
  }

  async function handleDelete() {
    await remove.mutateAsync({ realm, id: id! })
    navigate('/users')
  }

  async function handleImpersonate() {
    try {
      await impersonate.mutateAsync({ realm, id: id! })
      setImpersonateOpen(false)
    } catch {
      // The hook already toasted the API error; keep the dialog open.
    }
  }

  if (isLoading) return <PageLoader />
  if (error) return <ErrorMessage message={error.message} />
  if (!user) return <ErrorMessage message="User not found" />

  return (
    <div>
      <PageHeader
        title={user.username ?? 'User Detail'}
        icon={Users}
        breadcrumbs={[
          { label: 'Users', to: '/users' },
          { label: user.username ?? id! },
        ]}
        actions={
          <div className="flex items-center gap-3">
            <button
              onClick={() => setActionsEmailOpen(true)}
              className="px-4 py-2.5 border border-border-custom rounded-lg text-sm text-text-primary hover:border-border-hover hover:bg-white/[0.03] transition-all flex items-center gap-2"
            >
              <Mail className="w-4 h-4" />
              Execute Actions Email
            </button>
            <button
              onClick={() => setImpersonateOpen(true)}
              className="px-4 py-2.5 border border-border-custom rounded-lg text-sm text-text-primary hover:border-border-hover hover:bg-white/[0.03] transition-all flex items-center gap-2"
            >
              <KeyRound className="w-4 h-4" />
              Impersonate
            </button>
            <button
              onClick={() => setShowEdit(true)}
              className="px-4 py-2.5 border border-border-custom rounded-lg text-sm text-text-primary hover:border-border-hover hover:bg-white/[0.03] transition-all flex items-center gap-2"
            >
              <Pencil className="w-4 h-4" />
              Edit
            </button>
            <button
              onClick={() => setDeleteOpen(true)}
              className="px-4 py-2.5 border border-alert-red/30 rounded-lg text-sm text-alert-red hover:bg-alert-red/10 transition-all flex items-center gap-2"
            >
              <Trash2 className="w-4 h-4" />
              Delete
            </button>
          </div>
        }
      />

      <div className="flex gap-0 border-b border-border-custom mb-6">
        {tabs.map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-3 text-sm font-medium transition-colors border-b-2 ${
              activeTab === tab
                ? 'text-cyan-neon border-cyan-neon'
                : 'text-text-secondary border-transparent hover:text-text-primary'
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {activeTab === 'Details' && <DetailsTab user={user} />}
      {activeTab === 'Credentials' && (
        <CredentialsTab realm={realm} userId={id!} onResetPassword={() => setShowResetPassword(true)} />
      )}
      {activeTab === 'Role Mappings' && (
        <RoleMappingsSection realm={realm} entityId={id!} hooks={userRoleMappingHooks} />
      )}
      {activeTab === 'Groups' && <GroupsTab realm={realm} userId={id!} />}
      {activeTab === 'Sessions' && <SessionsTab realm={realm} userId={id!} />}

      <Modal open={showEdit} onClose={() => setShowEdit(false)} title="Edit User">
        <UserForm defaultValues={user} onSubmit={handleUpdate} onCancel={() => setShowEdit(false)} loading={update.isPending} />
      </Modal>

      <Modal open={showResetPassword} onClose={() => setShowResetPassword(false)} title="Reset Password">
        <ResetPasswordForm
          onSubmit={async (value, temporary) => {
            const body: CredentialRepresentation = { type: 'password', value, temporary }
            await resetPassword.mutateAsync({ realm, id: id!, body })
            setShowResetPassword(false)
          }}
          onCancel={() => setShowResetPassword(false)}
          loading={resetPassword.isPending}
        />
      </Modal>

      <Modal
        open={impersonateOpen}
        onClose={() => setImpersonateOpen(false)}
        title="Impersonate User"
        footer={
          <div className="flex justify-end gap-3">
            <button
              onClick={() => setImpersonateOpen(false)}
              disabled={impersonate.isPending}
              className="px-4 py-2.5 border border-border-custom rounded-lg text-sm text-text-primary hover:border-border-hover hover:bg-white/[0.03] transition-all disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              onClick={handleImpersonate}
              disabled={impersonate.isPending}
              className="px-5 py-2.5 bg-cyan-neon text-obsidian rounded-lg text-sm font-semibold uppercase tracking-wider hover:shadow-glow-cyan transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Impersonate
            </button>
          </div>
        }
      >
        <p className="text-sm text-text-secondary">
          This starts a session as <span className="text-white">{user.username}</span>. The action
          is audited: an admin event and a login event are recorded naming you as the impersonator.
        </p>
      </Modal>

      <ExecuteActionsEmailDialog
        open={actionsEmailOpen}
        onClose={() => setActionsEmailOpen(false)}
        loading={executeActionsEmail.isPending}
        onSubmit={async (actions, redirectUri, lifespan) => {
          try {
            await executeActionsEmail.mutateAsync({ realm, id: id!, actions, redirectUri, lifespan })
            setActionsEmailOpen(false)
          } catch {
            // The hook already toasted the API error; keep the dialog open.
          }
        }}
      />

      <DeleteConfirmModal open={deleteOpen} onClose={() => setDeleteOpen(false)} onConfirm={handleDelete} loading={remove.isPending} />
    </div>
  )
}

function DetailsTab({ user }: { user: UserRepresentation }) {
  const fields = [
    { label: 'Username', value: user.username, copyable: true },
    { label: 'Email', value: user.email, copyable: true },
    { label: 'First Name', value: user.first_name },
    { label: 'Last Name', value: user.last_name },
    { label: 'Enabled', value: user.enabled !== false ? 'Yes' : 'No' },
    { label: 'Email Verified', value: user.email_verified ? 'Yes' : 'No' },
    { label: 'Created At', value: user.created_at ? new Date(user.created_at).toLocaleString() : '—' },
  ]

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {fields.map((f) => (
        <div key={f.label} className="bg-surface-dark border border-border-custom rounded-xl p-4">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-text-secondary mb-1">{f.label}</div>
          <div className="flex items-center gap-2">
            <div className="text-sm text-white flex-1 min-w-0 truncate">{f.value || '—'}</div>
            {f.copyable && f.value && (
              <CopyButton text={f.value} size={14} />
            )}
          </div>
        </div>
      ))}
    </div>
  )
}

function ExecuteActionsEmailDialog({
  open,
  onClose,
  onSubmit,
  loading,
}: {
  open: boolean
  onClose: () => void
  onSubmit: (actions: string[], redirectUri?: string, lifespan?: number) => void
  loading?: boolean
}) {
  const { data: serverInfo, isLoading: infoLoading } = useServerInfo()
  const [selected, setSelected] = useState<string[]>([])
  const [redirectUri, setRedirectUri] = useState('')
  const [lifespan, setLifespan] = useState('')

  // Reset the form every time the dialog is (re)opened.
  useEffect(() => {
    if (open) {
      setSelected([])
      setRedirectUri('')
      setLifespan('')
    }
  }, [open])

  const parsedLifespan = lifespan.trim() ? Number(lifespan) : undefined

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Execute Actions Email"
      footer={
        <div className="flex justify-end gap-3">
          <button
            onClick={onClose}
            disabled={loading}
            className="px-4 py-2.5 border border-border-custom rounded-lg text-sm text-text-primary hover:border-border-hover hover:bg-white/[0.03] transition-all disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onClick={() =>
              onSubmit(
                selected,
                redirectUri.trim() || undefined,
                parsedLifespan !== undefined && !Number.isNaN(parsedLifespan) ? parsedLifespan : undefined
              )
            }
            disabled={loading || selected.length === 0}
            className="px-5 py-2.5 bg-cyan-neon text-obsidian rounded-lg text-sm font-semibold uppercase tracking-wider hover:shadow-glow-cyan transition-all disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Send Email
          </button>
        </div>
      }
    >
      <div className="flex flex-col gap-4">
        <p className="text-sm text-text-secondary">
          Sends the user an email with a link that lets them perform the selected required actions.
        </p>
        <div className="flex flex-col gap-1.5">
          <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Required Actions
          </span>
          <div className="flex flex-col gap-2 rounded-md border border-border-custom p-3">
            {infoLoading && <span className="text-xs text-text-tertiary">Loading...</span>}
            {!infoLoading && (serverInfo?.required_actions.length ?? 0) === 0 && (
              <span className="text-xs text-text-tertiary">No required actions available</span>
            )}
            {serverInfo?.required_actions.map((action) => {
              const checked = selected.includes(action.id)
              return (
                <label
                  key={action.id}
                  className="flex items-start gap-2 cursor-pointer"
                  title={action.description ?? undefined}
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={() =>
                      setSelected((prev) =>
                        checked ? prev.filter((v) => v !== action.id) : [...prev, action.id]
                      )
                    }
                    className="mt-0.5 w-4 h-4 rounded border-border-custom bg-white/[0.03] text-cyan-neon focus:ring-cyan-neon"
                  />
                  <span className="flex flex-col">
                    <span className="text-sm text-text-primary">{action.name ?? action.id}</span>
                    {action.description && (
                      <span className="text-[11px] text-text-tertiary leading-tight">
                        {action.description}
                      </span>
                    )}
                  </span>
                </label>
              )
            })}
          </div>
        </div>
        <div className="flex flex-col gap-1.5">
          <label htmlFor="execute-actions-redirect-uri" className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Redirect URI (optional)
          </label>
          <input
            id="execute-actions-redirect-uri"
            type="text"
            placeholder="https://app.example.com/after-actions"
            value={redirectUri}
            onChange={(e) => setRedirectUri(e.target.value)}
            className="w-full h-11 px-3 bg-surface-card border border-border-custom rounded-lg text-sm text-text-primary placeholder:text-text-tertiary focus:border-cyan-neon focus:shadow-[0_0_0_3px_rgba(0,229,255,0.1)] outline-none transition-all"
          />
        </div>
        <div className="flex flex-col gap-1.5">
          <label htmlFor="execute-actions-lifespan" className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Lifespan in seconds (optional)
          </label>
          <input
            id="execute-actions-lifespan"
            type="number"
            min={1}
            placeholder="43200"
            value={lifespan}
            onChange={(e) => setLifespan(e.target.value)}
            className="w-full h-11 px-3 bg-surface-card border border-border-custom rounded-lg text-sm text-text-primary placeholder:text-text-tertiary focus:border-cyan-neon focus:shadow-[0_0_0_3px_rgba(0,229,255,0.1)] outline-none transition-all"
          />
        </div>
      </div>
    </Modal>
  )
}

function CredentialsTab({
  realm,
  userId,
  onResetPassword,
}: {
  realm: string
  userId: string
  onResetPassword: () => void
}) {
  const { data: serverInfo } = useServerInfo()
  const { data: credentials, isLoading } = useUserCredentials(realm, userId)
  const updateLabel = useUpdateCredentialLabel()
  const deleteCredential = useDeleteCredential()
  const moveCredential = useMoveCredential()
  const [deleteTarget, setDeleteTarget] = useState<CredentialRepresentation | null>(null)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [editLabel, setEditLabel] = useState('')

  const credentialTypeMap = useMemo(() => {
    const map = new Map<string, EnumValueRepresentation>()
    serverInfo?.credential_types.forEach((ct) => map.set(ct.id, ct))
    return map
  }, [serverInfo])

  async function handleDeleteConfirm() {
    if (!deleteTarget?.id) return
    try {
      await deleteCredential.mutateAsync({ realm, id: userId, credentialId: deleteTarget.id })
      setDeleteTarget(null)
    } catch {
      // The hook already toasted the API error (e.g. the last-credential
      // guard's 400); keep the modal open so the reason stays visible.
    }
  }

  async function handleMove(index: number, direction: 'up' | 'down') {
    if (!credentials) return
    const current = credentials[index]
    const neighbor = direction === 'up' ? credentials[index - 1] : credentials[index + 1]
    if (!current?.id || !neighbor?.id) return
    // moveAfter semantics: the addressed credential lands immediately after the
    // target. Moving up == the credential above moves to after the current one.
    const [credentialId, newPreviousCredentialId] =
      direction === 'up' ? [neighbor.id, current.id] : [current.id, neighbor.id]
    try {
      await moveCredential.mutateAsync({ realm, id: userId, credentialId, newPreviousCredentialId })
    } catch {
      // toasted by the hook
    }
  }

  async function handleLabelSave(credentialId: string) {
    try {
      await updateLabel.mutateAsync({
        realm,
        id: userId,
        credentialId,
        label: editLabel.trim() || null,
      })
      setEditingId(null)
    } catch {
      // toasted by the hook; stay in edit mode
    }
  }

  return (
    <div>
      <div className="flex justify-end mb-4">
        <button
          onClick={onResetPassword}
          className="px-5 py-2.5 bg-cyan-neon text-obsidian rounded-lg text-sm font-semibold uppercase tracking-wider hover:shadow-glow-cyan transition-all"
        >
          Reset Password
        </button>
      </div>
      {isLoading ? (
        <Spinner />
      ) : credentials && credentials.length > 0 ? (
        <div className="flex flex-col gap-3">
          {credentials.map((c, index) => {
            const typeId = credentialTypeToString(c.type)
            const typeInfo = credentialTypeMap.get(typeId)
            const editing = editingId === c.id
            return (
              <div
                key={c.id ?? index}
                className="bg-surface-dark border border-border-custom rounded-xl p-4"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span
                        className="text-sm font-medium text-white"
                        title={typeInfo?.description ?? undefined}
                      >
                        {typeInfo?.name ?? typeId}
                      </span>
                      {c.temporary && <Badge variant="warning">Temporary</Badge>}
                    </div>
                    {editing ? (
                      <div className="flex items-center gap-2 mt-1">
                        <input
                          type="text"
                          aria-label="Credential label"
                          placeholder="Label (e.g. My laptop)"
                          value={editLabel}
                          onChange={(e) => setEditLabel(e.target.value)}
                          className="h-9 px-3 bg-surface-card border border-border-custom rounded-lg text-sm text-text-primary placeholder:text-text-tertiary focus:border-cyan-neon outline-none transition-all"
                        />
                        <button
                          onClick={() => handleLabelSave(c.id!)}
                          disabled={updateLabel.isPending}
                          aria-label="Save label"
                          className="p-1.5 border border-border-custom rounded-lg text-text-primary hover:bg-white/[0.03] transition-all disabled:opacity-50"
                        >
                          <Check className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => setEditingId(null)}
                          aria-label="Cancel label edit"
                          className="p-1.5 border border-border-custom rounded-lg text-text-secondary hover:bg-white/[0.03] transition-all"
                        >
                          <X className="w-4 h-4" />
                        </button>
                      </div>
                    ) : (
                      <div className="text-xs text-text-secondary">{c.user_label || '—'}</div>
                    )}
                    <div className="text-[11px] text-text-tertiary mt-1.5">
                      Created: {c.created_date ? new Date(c.created_date).toLocaleString() : '—'}
                      {' · '}Priority: {c.priority ?? '—'}
                    </div>
                  </div>
                  {!editing && (
                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        onClick={() => handleMove(index, 'up')}
                        disabled={index === 0 || moveCredential.isPending}
                        aria-label="Move up"
                        className="p-1.5 border border-border-custom rounded-lg text-text-secondary hover:text-text-primary hover:bg-white/[0.03] transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                      >
                        <ArrowUp className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => handleMove(index, 'down')}
                        disabled={index === credentials.length - 1 || moveCredential.isPending}
                        aria-label="Move down"
                        className="p-1.5 border border-border-custom rounded-lg text-text-secondary hover:text-text-primary hover:bg-white/[0.03] transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                      >
                        <ArrowDown className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => {
                          setEditingId(c.id!)
                          setEditLabel(c.user_label ?? '')
                        }}
                        disabled={!c.id}
                        aria-label="Edit label"
                        className="p-1.5 border border-border-custom rounded-lg text-text-secondary hover:text-text-primary hover:bg-white/[0.03] transition-all disabled:opacity-40"
                      >
                        <Pencil className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => setDeleteTarget(c)}
                        disabled={!c.id}
                        aria-label="Delete credential"
                        className="p-1.5 border border-alert-red/30 rounded-lg text-alert-red hover:bg-alert-red/10 transition-all disabled:opacity-40"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      ) : (
        <div className="text-sm text-text-secondary">No credentials.</div>
      )}

      <DeleteConfirmModal
        open={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDeleteConfirm}
        loading={deleteCredential.isPending}
        title="Delete Credential"
        description={`Delete the ${credentialTypeToString(deleteTarget?.type) || 'selected'} credential${
          deleteTarget?.user_label ? ` "${deleteTarget.user_label}"` : ''
        }? The API rejects deleting the user's last remaining credential.`}
      />
    </div>
  )
}

function ResetPasswordForm({
  onSubmit,
  onCancel,
  loading,
}: {
  onSubmit: (value: string, temporary: boolean) => void
  onCancel: () => void
  loading?: boolean
}) {
  const [value, setValue] = useState('')
  const [temporary, setTemporary] = useState(false)
  return (
    <div className="flex flex-col gap-4">
      <input
        type="password"
        placeholder="New password"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        className="w-full h-11 px-3 bg-surface-card border border-border-custom rounded-lg text-sm text-text-primary placeholder:text-text-tertiary focus:border-cyan-neon focus:shadow-[0_0_0_3px_rgba(0,229,255,0.1)] outline-none transition-all"
      />
      <label className="flex items-center gap-2 text-sm text-text-secondary cursor-pointer">
        <input
          type="checkbox"
          checked={temporary}
          onChange={(e) => setTemporary(e.target.checked)}
          className="w-4 h-4 rounded border-border-custom bg-white/[0.03] text-cyan-neon focus:ring-cyan-neon"
        />
        Temporary (must change on next login)
      </label>
      <div className="flex justify-end gap-3">
        <button
          onClick={onCancel}
          className="px-4 py-2.5 border border-border-custom rounded-lg text-sm text-text-primary hover:border-border-hover hover:bg-white/[0.03] transition-all"
        >
          Cancel
        </button>
        <button
          onClick={() => onSubmit(value, temporary)}
          disabled={!value || loading}
          className="px-5 py-2.5 bg-cyan-neon text-obsidian rounded-lg text-sm font-semibold uppercase tracking-wider hover:shadow-glow-cyan transition-all disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Reset
        </button>
      </div>
    </div>
  )
}

function GroupsTab({ realm, userId }: { realm: string; userId: string }) {
  const { data: allGroups } = useGroups(realm)
  const { data: userGroups } = useUserGroups(realm, userId)
  const add = useAddUserGroup()
  const remove = useRemoveUserGroup()

  const assigned = new Set(userGroups ?? [])
  const available = (allGroups ?? []).filter((g) => !assigned.has(g.id!))

  return (
    <TwoColumnPicker
      leftTitle="Available Groups"
      rightTitle="Assigned Groups"
      leftItems={available.map((g) => ({ id: g.id!, label: `${g.name} ${g.path ? `(${g.path})` : ''}` }))}
      rightItems={(userGroups ?? []).map((id) => {
        const group = allGroups?.find((g) => g.id === id)
        return { id, label: group?.name ?? id }
      })}
      onAdd={async (id) => {
        await add.mutateAsync({ realm, id: userId, groupId: id })
      }}
      onRemove={async (id) => {
        await remove.mutateAsync({ realm, id: userId, groupId: id })
      }}
    />
  )
}

function SessionsTab({ realm, userId }: { realm: string; userId: string }) {
  const { data: sessions, isLoading } = useUserSessions(realm, userId)
  const del = useDeleteSession()

  if (isLoading) return <PageLoader inline />

  return (
    <div className="flex flex-col gap-3">
      {sessions && sessions.length > 0 ? (
        sessions.map((s) => (
          <div
            key={s.id}
            className="bg-surface-dark border border-border-custom rounded-xl p-4 flex items-center justify-between"
          >
            <div>
              <div className="text-sm font-medium text-white flex items-center gap-2">
                {s.username} — {s.ip_address}
                {s.offline && <Badge variant="warning">Offline</Badge>}
              </div>
              <div className="text-xs text-text-secondary">
                Started: {s.started ? new Date(s.started * 1000).toLocaleString() : '—'} | Last Access:{' '}
                {s.last_access ? new Date(s.last_access * 1000).toLocaleString() : '—'}
              </div>
            </div>
            <button
              onClick={() => del.mutate({ realm, session: s.id })}
              className="px-3 py-1.5 border border-alert-red/30 rounded-lg text-xs text-alert-red hover:bg-alert-red/10 transition-all"
            >
              Logout
            </button>
          </div>
        ))
      ) : (
        <div className="text-sm text-text-secondary">No active sessions.</div>
      )}
    </div>
  )
}
