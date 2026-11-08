/**
 * Cleanup planning, confirmation, execution, quarantine, and audit.
 *
 * The confirmation for a cleanup is performed by this layer, inside the tool
 * call, through the Harness user-question service. The model cannot supply an
 * approval: `execute_cleanup_plan` accepts only a plan id, asks the human, and
 * receives an opaque approval id from the engine after that answer.
 */

import { EngineFailure } from '../engine/client.js'
import { askForConfirmation } from './confirm.js'
import { textResult } from './disk.js'

/**
 * @param {{ ctx: any, client: import('../engine/client.js').EngineClient }} deps
 */
export function registerCleanupTools({ ctx, client }) {
  ctx.effect(() =>
    ctx.tools.register({
      name: 'list_cleanup_candidates',
      description:
        'Read-only. Enumerate cleanup candidates under the user temp, Windows temp, and known cache directories (including Chrome/Edge profile caches and CrashDumps), or a subset you name. Returns the largest eligible files with size and age, plus totals and skip counts. Only files older than the safety window, outside reparse points, and inside allowed roots are listed. Feed up to 200 returned paths to create_cleanup_plan per plan.',
      parameters: {
        type: 'object',
        properties: {
          roots: { type: 'array', items: { type: 'string' }, description: 'Optional subset of temporary or cache roots.' },
          min_age_hours: { type: 'integer', default: 24, description: 'Only files older than this are listed.' },
          min_bytes: { type: 'integer', default: 0, description: 'Skip files smaller than this; useful to target high-value leftovers.' },
          limit: { type: 'integer', default: 200, description: 'Maximum candidates to return, largest first (1-500).' },
          max_seconds: { type: 'integer', default: 60 },
        },
        additionalProperties: false,
      },
      output: {
        schema: { type: 'object', properties: {}, additionalProperties: true },
        render: (_args, value) => textResult(value),
      },
      timeoutMs: 120_000,
      execute: (args, exec) => client.request('list_cleanup_candidates', args ?? {}, { signal: exec.signal, timeoutMs: 100_000 }),
    }),
  )

  ctx.effect(() =>
    ctx.tools.register({
      name: 'classify_files',
      description:
        'Read-only. Classify candidate paths before planning: category (temporary file, cache, recycle bin, personal document, system, unknown), risk level L1/L2/L4, eligibility, and the reasons. Use it when the user points at specific files and you are unsure whether they may be cleaned.',
      parameters: {
        type: 'object',
        properties: {
          paths: { type: 'array', items: { type: 'string' }},
        },
        required: ['paths'],
        additionalProperties: false,
      },
      output: {
        schema: { type: 'object', properties: {}, additionalProperties: true },
        render: (_args, value) => textResult(value),
      },
      timeoutMs: 60_000,
      execute: (args, exec) => client.request('classify_files', args ?? {}, { signal: exec.signal, timeoutMs: 40_000 }),
    }),
  )

  ctx.effect(() =>
    ctx.tools.register({
      name: 'create_cleanup_plan',
      description:
        'Read-only planning. Classify the given paths and build a durable cleanup plan from the eligible ones only (up to 200 paths per plan). Returns the plan id, risk level, per-item targets, and every excluded path with the reason. Creating a plan changes nothing on disk; execution is a separate, confirmed step.',
      parameters: {
        type: 'object',
        properties: {
          paths: { type: 'array', items: { type: 'string' }},
          max_items: { type: 'integer'},
        },
        required: ['paths'],
        additionalProperties: false,
      },
      output: {
        schema: { type: 'object', properties: {}, additionalProperties: true },
        render: (_args, value) => textResult(value),
      },
      timeoutMs: 90_000,
      execute: (args, exec) => client.request('create_cleanup_plan', args ?? {}, { signal: exec.signal, timeoutMs: 70_000 }),
    }),
  )

  ctx.effect(() =>
    ctx.tools.register({
      name: 'preview_action_plan',
      description:
        'Read-only. Re-read a stored plan and show its exact targets, risk level, expiry, and whether it is still pending. Use it immediately before asking the user to approve a plan.',
      parameters: {
        type: 'object',
        properties: { plan_id: { type: 'string'} },
        required: ['plan_id'],
        additionalProperties: false,
      },
      output: {
        schema: { type: 'object', properties: {}, additionalProperties: true },
        render: (_args, value) => textResult(value),
      },
      timeoutMs: 60_000,
      execute: (args, exec) => client.request('preview_action_plan', args ?? {}, { signal: exec.signal, timeoutMs: 40_000 }),
    }),
  )

  ctx.effect(() =>
    ctx.tools.register({
      name: 'execute_cleanup_plan',
      description:
        "Side effect. Execute a pending cleanup plan. This tool itself asks the user to confirm the exact targets through the Harness confirmation UI; the model cannot approve on the user's behalf, and an approval is valid for one execution only. Files are moved to the DiskGuardian quarantine, verified, and audited. If the user declines, nothing changes.",
      parameters: {
        type: 'object',
        properties: { plan_id: { type: 'string'} },
        required: ['plan_id'],
        additionalProperties: false,
      },
      output: {
        schema: { type: 'object', properties: {}, additionalProperties: true },
        render: (_args, value) => textResult(value),
      },
      timeoutMs: 180_000,
      async execute(args, exec) {
        const planId = args?.plan_id
        if (typeof planId !== 'string' || !planId) {
          throw new EngineFailure('E_INVALID_PARAMS', 'plan_id must be a non-empty string')
        }
        const plan = await client.request('preview_action_plan', { plan_id: planId }, { signal: exec.signal, timeoutMs: 40_000 })
        if (plan.expired) {
          throw new EngineFailure('E_PLAN_EXPIRED', 'the plan expired; create a new plan before executing')
        }
        if (plan.status !== 'pending') {
          throw new EngineFailure('E_INVALID_STATE', `the plan state is ${plan.status}, not pending`)
        }
        if (plan.plan_type !== 'cleanup') {
          throw new EngineFailure('E_INVALID_PARAMS', 'this plan is not a cleanup plan')
        }

        const items = Array.isArray(plan.items) ? plan.items : []
        const totalBytes = items.reduce((sum, item) => sum + Number(item.size_bytes ?? 0), 0)
        const decision = await askForConfirmation(ctx, exec, {
          id: 'diskguardian-confirm-cleanup',
          header: 'DiskGuardian 清理确认',
          question: `计划 ${planId}：把 ${items.length} 个文件（共 ${totalBytes} 字节）移入隔离区。移动后可恢复；不会永久删除。`,
          detail: items
            .slice(0, 25)
            .map((item, index) => `${index + 1}. ${item.target} (${item.size_bytes ?? 0} B)`)
            .join('\n'),
          confirmLabel: '确认执行',
          cancelLabel: '取消',
          confirmDescription: '执行计划，文件移入隔离区',
          cancelDescription: '不执行，不修改任何文件',
        })
        if (!decision.confirmed) {
          return {
            executed: false,
            plan_id: planId,
            declined: true,
            reason: decision.reason,
            note: 'No file was moved and the plan is still pending.',
          }
        }

        const issued = await client.request(
          'issue_approval',
          { plan_id: planId, source: 'harness-user-question' },
          { signal: exec.signal, timeoutMs: 40_000 },
        )
        return client.request(
          'execute_cleanup_plan',
          { plan_id: planId, approval_id: issued.approval_id },
          { signal: exec.signal, timeoutMs: 150_000 },
        )
      },
    }),
  )

  ctx.effect(() =>
    ctx.tools.register({
      name: 'purge_quarantine',
      description:
        'Side effect, irreversible. Permanently delete quarantined copies so their space is actually freed. Quarantine sits on the same volume as the cleaned files, so moving files into it frees no space until they are purged. This tool previews the exact items, asks the human to confirm, then deletes only files whose SHA-256 still matches the recorded hash. Use it after the user confirms they do not need to restore those items.',
      parameters: {
        type: 'object',
        properties: {
          quarantine_ids: { type: 'array', items: { type: 'string' }, description: 'Specific records to purge.' },
          older_than_days: { type: 'integer', description: 'Only items quarantined at least this many days ago.' },
          all: { type: 'boolean', description: 'Purge every record still in quarantine.' },
        },
        additionalProperties: false,
      },
      output: {
        schema: { type: 'object', properties: {}, additionalProperties: true },
        render: (_args, value) => textResult(value),
      },
      timeoutMs: 300_000,
      async execute(args, exec) {
        const params = { ...(args ?? {}) }
        const choice = Boolean(params.all)
          ? '全部隔离项'
          : Array.isArray(params.quarantine_ids) && params.quarantine_ids.length > 0
            ? `${params.quarantine_ids.length} 个指定隔离项`
            : params.older_than_days
              ? `超过 ${params.older_than_days} 天的隔离项`
              : null
        if (!choice) {
          throw new EngineFailure('E_INVALID_PARAMS', 'pass quarantine_ids, older_than_days, or all=true')
        }

        const preview = await client.request('purge_quarantine', { ...params, dry_run: true }, { signal: exec.signal, timeoutMs: 40_000 })
        if (!preview.count) {
          return { purged: 0, note: 'Nothing matches; the quarantine is already empty for this filter.' }
        }
        const decision = await askForConfirmation(ctx, exec, {
          id: 'diskguardian-confirm-purge',
          header: 'DiskGuardian 清空隔离区',
          question: `即将永久删除 ${choice}：${preview.count} 个文件，共 ${preview.bytes} 字节。此操作不可恢复。`,
          detail: (preview.items ?? [])
            .slice(0, 20)
            .map((item, index) => `${index + 1}. ${item.original_path} (${item.bytes} B)`)
            .join('\n'),
          confirmLabel: '永久删除',
          cancelLabel: '取消',
          confirmDescription: '释放磁盘空间，不可恢复',
          cancelDescription: '保留隔离文件，可继续恢复',
        })
        if (!decision.confirmed) {
          return { purged: 0, declined: true, reason: decision.reason, note: 'Nothing was deleted.' }
        }
        return client.request('purge_quarantine', params, { signal: exec.signal, timeoutMs: 240_000 })
      },
    }),
  )

  ctx.effect(() =>
    ctx.tools.register({
      name: 'restore_quarantined_item',
      description:
        'Side effect. Restore one quarantined file to its original path and verify its size and SHA-256 afterwards. Refuses when the original path already exists. Use it when the user wants a cleaned file back.',
      parameters: {
        type: 'object',
        properties: { quarantine_id: { type: 'string'} },
        required: ['quarantine_id'],
        additionalProperties: false,
      },
      output: {
        schema: { type: 'object', properties: {}, additionalProperties: true },
        render: (_args, value) => textResult(value),
      },
      timeoutMs: 120_000,
      execute: (args, exec) => client.request('restore_quarantined_item', args ?? {}, { signal: exec.signal, timeoutMs: 90_000 }),
    }),
  )

  ctx.effect(() =>
    ctx.tools.register({
      name: 'list_quarantine',
      description:
        'Read-only. List quarantined items with their original path, size, hash, plan, and state. Use it before a restore or when the user asks what was cleaned.',
      parameters: {
        type: 'object',
        properties: { limit: { type: 'integer', default: 100 } },
        additionalProperties: false,
      },
      output: {
        schema: { type: 'object', properties: {}, additionalProperties: true },
        render: (_args, value) => textResult(value),
      },
      timeoutMs: 60_000,
      execute: (args, exec) => client.request('list_quarantine', args ?? {}, { signal: exec.signal, timeoutMs: 40_000 }),
    }),
  )

  ctx.effect(() =>
    ctx.tools.register({
      name: 'get_audit_log',
      description:
        'Read-only. Read the local audit log: plan creation, approval issue, per-item quarantine results, verification, and restores. Use it to answer "what did you do" with recorded facts instead of recollection.',
      parameters: {
        type: 'object',
        properties: { limit: { type: 'integer', default: 100 } },
        additionalProperties: false,
      },
      output: {
        schema: { type: 'object', properties: {}, additionalProperties: true },
        render: (_args, value) => textResult(value),
      },
      timeoutMs: 60_000,
      execute: (args, exec) => client.request('get_audit_log', args ?? {}, { signal: exec.signal, timeoutMs: 40_000 }),
    }),
  )
}
