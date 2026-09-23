// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState, useEffect } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { UsersRound, Trash2, Plus } from 'lucide-react'
import { useAuthStore } from '../../state/authStore'
import {
  useGroup,
  useUpdateGroup,
  useDeleteGroup,
  useGroups,
  useGroupRealmRoles,
  useAvailableGroupRealmRoles,
  useGroupClientRoles,
  useAvailableGroupClientRoles,
  useAddGroupRealmRoles,
  useRemoveGroupRealmRoles,
  useAddGroupClientRoles,
  useRemoveGroupClientRoles,
} from '../../api/hooks/useGroups'
import { useGroupMembers, useCreateChildGroup, useMoveGroup } from '../../api/hooks/useGroupTree'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../../components/ui/tabs'
import PageLoader from '../../components/ui/PageLoader'
import ErrorMessage from '../../components/ui/ErrorMessage'
import GroupForm from '../../components/domain/GroupForm'
import RoleMappingsSection, { type RoleMappingsHooks } from '../../components/domain/RoleMappingsSection'
import DeleteConfirmModal from '../../components/domain/DeleteConfirmModal'
import { Table, Thead, Tbody, Tr, Th, Td } from '../../components/ui/Table'
import PageHeader from '@/components/layout/PageHeader'
import type { GroupRepresentation } from '@generated'

const MEMBERS_PER_PAGE = 20

const groupRoleMappingHooks: RoleMappingsHooks = {
  useAssignedRealmRoles: useGroupRealmRoles,
  useAvailableRealmRoles: useAvailableGroupRealmRoles,
  useAssignedClientRoles: useGroupClientRoles,
  useAvailableClientRoles: useAvailableGroupClientRoles,
  useAddRealmRoles: useAddGroupRealmRoles,
  useRemoveRealmRoles: useRemoveGroupRealmRoles,
  useAddClientRoles: useAddGroupClientRoles,
  useRemoveClientRoles: useRemoveGroupClientRoles,
}

export default function GroupEditPage() {
  const navigate = useNavigate()
  const { id } = useParams<{ id: string }>()
  const realm = useAuthStore((s) => s.currentRealm)!

  const { data: group, isLoading, error } = useGroup(realm, id!)
  const update = useUpdateGroup()
  const remove = useDeleteGroup()

  const [deleteOpen, setDeleteOpen] = useState(false)

  async function handleUpdate(data: GroupRepresentation) {
    await update.mutateAsync({ realm, id: id!, body: data })
    navigate('/groups')
  }

  async function handleDelete() {
    await remove.mutateAsync({ realm, id: id! })
    navigate('/groups')
  }

  if (isLoading) return <PageLoader />
  if (error) return <ErrorMessage message={error.message} />
  if (!group) return <ErrorMessage message="Group not found" />

  return (
    <div>
      <PageHeader
        title="Edit Group"
        icon={UsersRound}
        breadcrumbs={[
          { label: 'Groups', to: '/groups' },
          { label: group.name },
        ]}
        actions={
          <button
            onClick={() => setDeleteOpen(true)}
            className="px-4 py-2.5 border border-alert-red/30 rounded-lg text-sm text-alert-red hover:bg-alert-red/10 transition-all flex items-center gap-2"
          >
            <Trash2 className="w-4 h-4" />
            Delete
          </button>
        }
      />

      <Tabs defaultValue="settings">
        <TabsList variant="line" className="mb-6">
          <TabsTrigger value="settings">Settings</TabsTrigger>
          <TabsTrigger value="children">Children</TabsTrigger>
          <TabsTrigger value="members">Members</TabsTrigger>
          <TabsTrigger value="role-mappings">Role Mappings</TabsTrigger>
        </TabsList>

        <TabsContent value="settings">
          <div className="flex flex-col gap-6 max-w-2xl">
            <div className="bg-surface-dark border border-border-custom rounded-xl p-6">
              <GroupForm
                defaultValues={group}
                onSubmit={handleUpdate}
                onCancel={() => navigate('/groups')}
                loading={update.isPending}
              />
            </div>
            <MoveGroupSection realm={realm} group={group} />
          </div>
        </TabsContent>

        <TabsContent value="children">
          <ChildrenTab realm={realm} group={group} />
        </TabsContent>

        <TabsContent value="members">
          <MembersTab realm={realm} groupId={id!} />
        </TabsContent>

        <TabsContent value="role-mappings">
          <RoleMappingsSection realm={realm} entityId={id!} hooks={groupRoleMappingHooks} />
        </TabsContent>
      </Tabs>

      <DeleteConfirmModal
        open={deleteOpen}
        onClose={() => setDeleteOpen(false)}
        onConfirm={handleDelete}
        loading={remove.isPending}
      />
    </div>
  )
}

function MoveGroupSection({ realm, group }: { realm: string; group: GroupRepresentation }) {
  const { data: allGroups } = useGroups(realm)
  const moveGroup = useMoveGroup()
  const [target, setTarget] = useState<string>(group.parent_id ?? '')

  // Re-sync the picker when the group's parent changes (e.g. after a move).
  useEffect(() => {
    setTarget(group.parent_id ?? '')
  }, [group.id, group.parent_id])

  // The group itself and its descendants can never be a valid parent — the
  // backend would reject the move as a cycle anyway.
  const options = (allGroups ?? []).filter((g) => {
    if (!g.id || g.id === group.id) return false
    if (group.path && g.path && g.path.startsWith(`${group.path}/`)) return false
    return true
  })

  const changed = target !== (group.parent_id ?? '')

  async function handleMove() {
    // Tri-state parent_id: `null` moves to the root, an id moves under that
    // parent. The button is only enabled on change, so `undefined` (preserve)
    // never needs to be sent from here.
    try {
      await moveGroup.mutateAsync({
        realm,
        id: group.id!,
        body: { name: group.name, parent_id: target === '' ? null : target },
      })
    } catch {
      // The hook already toasted the API error (e.g. a cycle rejection).
    }
  }

  return (
    <div className="bg-surface-dark border border-border-custom rounded-xl p-6">
      <h3 className="text-sm font-semibold text-white mb-1">Move Group</h3>
      <p className="text-xs text-text-secondary mb-4">
        Current path: <span className="font-mono">{group.path ?? '—'}</span>
      </p>
      <div className="flex items-end gap-3">
        <div className="flex flex-col gap-1.5 flex-1">
          <label
            htmlFor="group-parent-select"
            className="text-xs font-semibold uppercase tracking-wider text-muted-foreground"
          >
            Parent Group
          </label>
          <select
            id="group-parent-select"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            className="h-11 px-3 bg-surface-card border border-border-custom rounded-lg text-sm text-text-primary focus:border-cyan-neon outline-none transition-all"
          >
            <option value="">None (root)</option>
            {options.map((g) => (
              <option key={g.id} value={g.id!}>
                {g.path ?? g.name}
              </option>
            ))}
          </select>
        </div>
        <button
          onClick={handleMove}
          disabled={!changed || moveGroup.isPending}
          className="px-5 py-2.5 bg-cyan-neon text-obsidian rounded-lg text-sm font-semibold uppercase tracking-wider hover:shadow-glow-cyan transition-all disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Move
        </button>
      </div>
    </div>
  )
}

function ChildrenTab({ realm, group }: { realm: string; group: GroupRepresentation }) {
  const navigate = useNavigate()
  const { data: allGroups } = useGroups(realm)
  const createChild = useCreateChildGroup()
  const [name, setName] = useState('')

  // `get_group` does not embed children, so derive them from the flat list.
  const children = (allGroups ?? []).filter((g) => g.parent_id === group.id)

  async function handleCreate() {
    const trimmed = name.trim()
    if (!trimmed) return
    try {
      await createChild.mutateAsync({ realm, id: group.id!, body: { name: trimmed } })
      setName('')
    } catch {
      // toasted by the hook
    }
  }

  return (
    <div className="max-w-2xl">
      <div className="flex items-end gap-3 mb-6">
        <div className="flex flex-col gap-1.5 flex-1">
          <label
            htmlFor="child-group-name"
            className="text-xs font-semibold uppercase tracking-wider text-muted-foreground"
          >
            New Sub-group
          </label>
          <input
            id="child-group-name"
            type="text"
            placeholder="Sub-group name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="h-11 px-3 bg-surface-card border border-border-custom rounded-lg text-sm text-text-primary placeholder:text-text-tertiary focus:border-cyan-neon focus:shadow-[0_0_0_3px_rgba(0,229,255,0.1)] outline-none transition-all"
          />
        </div>
        <button
          onClick={handleCreate}
          disabled={!name.trim() || createChild.isPending}
          className="px-5 py-2.5 bg-cyan-neon text-obsidian rounded-lg text-sm font-semibold uppercase tracking-wider hover:shadow-glow-cyan transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
        >
          <Plus className="w-4 h-4" />
          Create
        </button>
      </div>

      {children.length > 0 ? (
        <Table>
          <Thead>
            <Tr>
              <Th>Name</Th>
              <Th>Path</Th>
            </Tr>
          </Thead>
          <Tbody>
            {children.map((g) => (
              <Tr key={g.id} onClick={() => g.id && navigate(`/groups/${g.id}`)}>
                <Td>
                  <span className="text-sm font-medium text-white">{g.name}</span>
                </Td>
                <Td>
                  <span className="text-text-secondary font-mono text-xs">{g.path || '—'}</span>
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      ) : (
        <div className="text-sm text-text-secondary">No sub-groups.</div>
      )}
    </div>
  )
}

function MembersTab({ realm, groupId }: { realm: string; groupId: string }) {
  const navigate = useNavigate()
  const [first, setFirst] = useState(0)
  const { data: members, isLoading } = useGroupMembers(realm, groupId, {
    first,
    max: MEMBERS_PER_PAGE,
  })

  if (isLoading) return <PageLoader inline />

  return (
    <div>
      {members && members.length > 0 ? (
        <Table>
          <Thead>
            <Tr>
              <Th>Username</Th>
              <Th>Email</Th>
              <Th>Enabled</Th>
            </Tr>
          </Thead>
          <Tbody>
            {members.map((m) => (
              <Tr key={m.id} onClick={() => m.id && navigate(`/users/${m.id}`)}>
                <Td>
                  <span className="text-sm font-medium text-white">{m.username ?? '—'}</span>
                </Td>
                <Td>
                  <span className="text-text-secondary">{m.email || '—'}</span>
                </Td>
                <Td>
                  <span className="text-text-secondary">{m.enabled !== false ? 'Yes' : 'No'}</span>
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      ) : (
        <div className="text-sm text-text-secondary">No members in this group.</div>
      )}

      <div className="flex items-center justify-between mt-4 max-w-2xl">
        <span className="text-xs text-text-tertiary">
          {members && members.length > 0
            ? `Showing ${first + 1}–${first + members.length}`
            : 'Showing 0'}
        </span>
        <div className="flex gap-2">
          <button
            onClick={() => setFirst((f) => Math.max(0, f - MEMBERS_PER_PAGE))}
            disabled={first === 0}
            className="px-4 py-2 border border-border-custom rounded-lg text-sm text-text-primary hover:border-border-hover hover:bg-white/[0.03] transition-all disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Previous
          </button>
          <button
            onClick={() => setFirst((f) => f + MEMBERS_PER_PAGE)}
            disabled={(members?.length ?? 0) < MEMBERS_PER_PAGE}
            className="px-4 py-2 border border-border-custom rounded-lg text-sm text-text-primary hover:border-border-hover hover:bg-white/[0.03] transition-all disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  )
}
