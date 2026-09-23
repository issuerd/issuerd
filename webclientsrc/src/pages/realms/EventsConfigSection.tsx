// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState } from 'react'
import { Save, Eraser } from 'lucide-react'
import {
  useEventsConfig,
  useUpdateEventsConfig,
  useClearEvents,
  useClearAdminEvents,
} from '../../api/hooks/useEventsConfig'
import { useServerInfo } from '../../api/hooks/useServerInfo'
import FormSection from '@/components/ui/FormSection'
import FormSwitch from '@/components/ui/FormSwitch'
import Input from '@/components/ui/Input'
import Button from '@/components/ui/Button'
import PageLoader from '@/components/ui/PageLoader'
import ErrorMessage from '@/components/ui/ErrorMessage'
import ConfirmActionModal from './ConfirmActionModal'
import type { RealmEventsConfigRepresentation } from '@generated'

interface EventsConfigSectionProps {
  /** Realm name (URL segment). */
  realm: string
}

type ClearTarget = 'events' | 'admin-events' | null

/**
 * Events tab content: per-realm event recording configuration
 * (`GET/PUT .../events/config`) plus maintenance actions that wipe the stored
 * event / admin-event history (`DELETE .../events`, `DELETE .../admin-events`).
 *
 * Unlike the rest of realm settings this surface has its own Save button — it
 * persists through the events-config endpoint, not the realm PUT.
 */
export default function EventsConfigSection({ realm }: EventsConfigSectionProps) {
  const { data: config, isLoading, error } = useEventsConfig(realm)
  const updateConfig = useUpdateEventsConfig()
  const clearEvents = useClearEvents()
  const clearAdminEvents = useClearAdminEvents()
  const { data: serverInfo, isLoading: infoLoading } = useServerInfo()

  const [form, setForm] = useState<Partial<RealmEventsConfigRepresentation>>({})
  const [saveError, setSaveError] = useState<string | null>(null)
  const [clearTarget, setClearTarget] = useState<ClearTarget>(null)

  const values: RealmEventsConfigRepresentation = { ...config, ...form }

  function patch<K extends keyof RealmEventsConfigRepresentation>(
    key: K,
    value: RealmEventsConfigRepresentation[K]
  ) {
    setForm((prev) => ({ ...prev, [key]: value }))
  }

  function toggleListener(id: string) {
    const current = values.eventsListeners ?? []
    patch(
      'eventsListeners',
      current.includes(id) ? current.filter((v) => v !== id) : [...current, id]
    )
  }

  async function handleSave() {
    setSaveError(null)
    try {
      await updateConfig.mutateAsync({
        realm,
        body: {
          eventsEnabled: values.eventsEnabled ?? false,
          eventsExpiration: values.eventsExpiration ?? 0,
          adminEventsEnabled: values.adminEventsEnabled ?? false,
          adminEventsDetailsEnabled: values.adminEventsDetailsEnabled ?? false,
          eventsListeners: values.eventsListeners ?? [],
        },
      })
      setForm({})
    } catch (err) {
      setSaveError((err as Error).message)
    }
  }

  async function handleClearConfirm() {
    try {
      if (clearTarget === 'events') await clearEvents.mutateAsync(realm)
      if (clearTarget === 'admin-events') await clearAdminEvents.mutateAsync(realm)
      setClearTarget(null)
    } catch {
      // Failure is surfaced by the mutation's error toast; keep the modal open.
    }
  }

  const hasChanges = Object.keys(form).length > 0
  const adminEventsOn = values.adminEventsEnabled ?? false

  if (isLoading) return <PageLoader inline />
  if (error) return <ErrorMessage message={error.message} />

  return (
    <>
      <FormSection
        title="Event Recording"
        description="Which events this realm records and how long they are kept"
        sectionId="realm-events-recording"
        configuredCount={
          [values.eventsEnabled, values.adminEventsEnabled].filter(Boolean).length
        }
        totalCount={2}
      >
        <FormSwitch
          label="Events enabled"
          helperText="Record login and account events for this realm"
          checked={values.eventsEnabled ?? false}
          onChange={(v) => patch('eventsEnabled', v)}
        />
        <Input
          label="Events expiration (seconds)"
          type="number"
          min={0}
          value={values.eventsExpiration ?? 0}
          onChange={(e) =>
            patch('eventsExpiration', e.target.value === '' ? null : Number(e.target.value))
          }
          helperText="How long stored events are retained — 0 keeps them forever"
        />
        <FormSwitch
          label="Admin events enabled"
          helperText="Record administrative operations on this realm"
          checked={adminEventsOn}
          onChange={(v) => patch('adminEventsEnabled', v)}
        />
        <FormSwitch
          label="Include representations"
          helperText="Store the request body with each admin event"
          checked={values.adminEventsDetailsEnabled ?? false}
          disabled={!adminEventsOn}
          onChange={(v) => patch('adminEventsDetailsEnabled', v)}
        />

        <div className="flex flex-col gap-1.5">
          <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Event Listeners
          </span>
          <div className="flex flex-col gap-2 rounded-md border border-border-custom p-3">
            {infoLoading && <span className="text-xs text-text-tertiary">Loading...</span>}
            {!infoLoading && (serverInfo?.event_listeners.length ?? 0) === 0 && (
              <span className="text-xs text-text-tertiary">No event listeners available</span>
            )}
            {serverInfo?.event_listeners.map((listener) => {
              const checked = (values.eventsListeners ?? []).includes(listener.id)
              return (
                <label
                  key={listener.id}
                  className="flex items-start gap-2 cursor-pointer"
                  title={listener.description ?? undefined}
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={() => toggleListener(listener.id)}
                    className="mt-0.5 w-4 h-4 rounded border-border-custom bg-white/[0.03] text-cyan-neon focus:ring-cyan-neon"
                  />
                  <span className="flex flex-col">
                    <span className="text-sm text-text-primary">
                      {listener.name ?? listener.id}
                    </span>
                    {listener.description && (
                      <span className="text-[11px] text-text-tertiary leading-tight">
                        {listener.description}
                      </span>
                    )}
                  </span>
                </label>
              )
            })}
          </div>
          <span className="text-xs text-text-tertiary">
            Listener SPIs that receive this realm's events
          </span>
        </div>

        <div className="flex items-center gap-3">
          <Button
            type="button"
            size="sm"
            loading={updateConfig.isPending}
            disabled={!hasChanges}
            onClick={handleSave}
          >
            <Save className="w-4 h-4 mr-1" />
            Save
          </Button>
          {saveError && (
            <span className="text-sm text-alert-red" role="alert">
              {saveError}
            </span>
          )}
        </div>
      </FormSection>

      <FormSection
        title="Maintenance"
        description="Permanently wipe stored event history for this realm"
        sectionId="realm-events-maintenance"
      >
        <div className="flex items-center gap-3">
          <Button
            type="button"
            variant="danger"
            size="sm"
            onClick={() => setClearTarget('events')}
          >
            <Eraser className="w-4 h-4 mr-1" />
            Clear events
          </Button>
          <Button
            type="button"
            variant="danger"
            size="sm"
            onClick={() => setClearTarget('admin-events')}
          >
            <Eraser className="w-4 h-4 mr-1" />
            Clear admin events
          </Button>
        </div>
      </FormSection>

      <ConfirmActionModal
        open={clearTarget !== null}
        onClose={() => setClearTarget(null)}
        onConfirm={handleClearConfirm}
        loading={clearEvents.isPending || clearAdminEvents.isPending}
        title={clearTarget === 'admin-events' ? 'Clear admin events' : 'Clear events'}
        description={
          clearTarget === 'admin-events'
            ? 'Delete all stored admin events for this realm? This cannot be undone.'
            : 'Delete all stored events for this realm? This cannot be undone.'
        }
        confirmLabel="Clear"
      />
    </>
  )
}
