// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>

import { useState } from 'react'
import { Upload } from 'lucide-react'
import { usePartialImport } from '../../api/hooks/useRealmAdminActions'
import FormSection from '@/components/ui/FormSection'
import FormTextarea from '@/components/ui/FormTextarea'
import FormSelect from '@/components/ui/FormSelect'
import Button from '@/components/ui/Button'
import { Table, Thead, Tbody, Tr, Th, Td } from '@/components/ui/Table'
import type {
  IfResourceExists,
  PartialImportRepresentation,
  PartialImportResultRepresentation,
} from '@generated'

interface PartialImportSectionProps {
  /** Realm name (URL segment). */
  realm: string
}

/**
 * Conflict strategies accepted by the partial-import endpoint. This is a fixed
 * API union (`IfResourceExists`) with no serverinfo enum behind it.
 */
const STRATEGY_OPTIONS: Array<{ value: IfResourceExists; label: string; description: string }> = [
  { value: 'FAIL', label: 'Fail', description: 'Abort the import when a resource already exists' },
  { value: 'SKIP', label: 'Skip', description: 'Keep existing resources, import only new ones' },
  { value: 'OVERWRITE', label: 'Overwrite', description: 'Replace existing resources with the imported ones' },
]

/**
 * Partial import: pastes or uploads a realm-partial JSON document
 * and imports selected resources into the realm, rendering the per-resource
 * outcome list returned by the server.
 */
export default function PartialImportSection({ realm }: PartialImportSectionProps) {
  const partialImport = usePartialImport()

  const [json, setJson] = useState('')
  const [strategy, setStrategy] = useState<IfResourceExists>('FAIL')
  const [importError, setImportError] = useState<string | null>(null)
  const [result, setResult] = useState<PartialImportResultRepresentation | null>(null)

  async function handleFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    try {
      setJson(await file.text())
      setImportError(null)
    } catch {
      setImportError('Could not read the selected file')
    }
  }

  async function handleImport() {
    setImportError(null)
    setResult(null)
    let body: PartialImportRepresentation
    try {
      body = JSON.parse(json) as PartialImportRepresentation
    } catch (err) {
      setImportError(`Invalid JSON: ${(err as Error).message}`)
      return
    }
    try {
      setResult(await partialImport.mutateAsync({ realm, body, ifResourceExists: strategy }))
    } catch (err) {
      setImportError((err as Error).message)
    }
  }

  return (
    <FormSection
      title="Partial Import"
      description="Import users, clients, groups, roles, or identity providers from a realm-partial JSON document"
      sectionId="realm-actions-partial-import"
    >
      <FormTextarea
        label="Realm partial JSON"
        value={json}
        onChange={(e) => setJson(e.target.value)}
        rows={8}
        monospace
        placeholder='{"users": [...], "clients": [...]}'
        helperText="Paste a partial realm export, or load it from a file below"
        error={importError ?? undefined}
      />
      <div className="flex flex-col gap-1.5">
        <label
          htmlFor="partial-import-file"
          className="text-xs font-semibold uppercase tracking-wider text-text-secondary"
        >
          Load from file
        </label>
        <input
          id="partial-import-file"
          type="file"
          accept="application/json,.json"
          onChange={handleFile}
          className="text-sm text-text-secondary file:mr-3 file:px-3 file:py-1.5 file:rounded-md file:border file:border-border-custom file:bg-surface-card file:text-text-primary file:text-xs hover:file:bg-white/[0.05]"
        />
      </div>
      <FormSelect
        label="If a resource exists"
        options={STRATEGY_OPTIONS}
        value={strategy}
        onChange={(v) => setStrategy(v as IfResourceExists)}
        helperText="Conflict strategy applied when an imported resource already exists"
      />
      <div>
        <Button
          type="button"
          size="sm"
          loading={partialImport.isPending}
          disabled={!json.trim()}
          onClick={handleImport}
        >
          <Upload className="w-4 h-4 mr-1" />
          Import
        </Button>
      </div>

      {result && (
        <div className="flex flex-col gap-3" data-testid="partial-import-result">
          <div className="flex items-center gap-4 text-sm">
            <span className="text-matrix-green">{result.added} added</span>
            <span className="text-text-secondary">{result.skipped} skipped</span>
            <span className="text-cyan-neon">{result.updated} updated</span>
          </div>
          <Table>
            <Thead>
              <Tr>
                <Th>Resource Type</Th>
                <Th>Resource Name</Th>
                <Th>Action</Th>
              </Tr>
            </Thead>
            <Tbody>
              {result.results.map((entry, idx) => (
                <Tr key={`${entry.resourceType}-${entry.resourceName}-${idx}`}>
                  <Td>{entry.resourceType}</Td>
                  <Td>{entry.resourceName}</Td>
                  <Td>{entry.action}</Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        </div>
      )}
    </FormSection>
  )
}
