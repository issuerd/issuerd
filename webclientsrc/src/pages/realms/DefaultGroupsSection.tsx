// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import FormSection from '@/components/ui/FormSection'
import FormTextarea from '@/components/ui/FormTextarea'
import type { RealmRepresentation } from '@generated'

/** Splits a newline-separated textarea value into a trimmed array. */
function arrayFromLines(text: string): string[] {
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
}

/** Joins an array field into the newline-separated textarea convention. */
function linesFromArray(arr: string[] | null | undefined): string {
  return (arr ?? []).join('\n')
}

interface DefaultGroupsSectionProps {
  /** Merged realm values from the settings page (server data + local edits). */
  values: Partial<RealmRepresentation>
  /** Patches a field into the settings page's pending-change state. */
  onPatch: <K extends keyof RealmRepresentation>(key: K, value: RealmRepresentation[K]) => void
}

/**
 * Default groups: group paths automatically assigned to every newly
 * created user. One path per line; saved through the settings page's realm PUT.
 */
export default function DefaultGroupsSection({ values, onPatch }: DefaultGroupsSectionProps) {
  return (
    <FormSection
      title="Default Groups"
      description="Groups every new realm user joins automatically"
      sectionId="realm-security-default-groups"
      configuredCount={(values.defaultGroups ?? []).length > 0 ? 1 : 0}
      totalCount={1}
    >
      <FormTextarea
        label="Group paths"
        value={linesFromArray(values.defaultGroups)}
        onChange={(e) => onPatch('defaultGroups', arrayFromLines(e.target.value))}
        rows={4}
        monospace
        placeholder="/developers"
        helperText="One group path per line (e.g. /developers)"
      />
    </FormSection>
  )
}
