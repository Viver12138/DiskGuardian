/**
 * Reversible startup-entry management.
 *
 * Disabling removes one registry Run/RunOnce value after the engine stores its
 * exact data; enabling writes it back. Both directions go through the same
 * plan + one-time approval path as cleanup, and the confirmation happens here,
 * inside the tool call.
 */

import { EngineFailure } from '../engine/client.js'
import { askForConfirmation } from './confirm.js'
import { textResult } from './disk.js'

/**
 * @param {{ ctx: any, client: import('../engine/client.js').EngineClient }} deps
 */
export function registerStartupTools({ ctx, client }) {
  ctx.effect(() =>
    ctx.tools.register({
      name: 'manage_startup_entry',
      description:
        'Side effect (reversible). Disable or re-enable one registry startup entry (HKCU/HKLM Run and RunOnce). The engine stores the exact original value before removing it, so re-enabling restores it to the same key. This tool asks the human to confirm the exact entry through the Harness confirmation UI; the model cannot approve. It never touches scheduled tasks or services.',
      parameters: {
        type: 'object',
        properties: {
          name: { type: 'string', description: 'Registry value name, as shown by inspect_startup_entries.' },
          action: { type: 'string', enum: ['disable', 'enable'] },
          scope: { type: 'string', enum: ['user', 'machine'], description: 'Optional hive filter when the same name exists twice.' },
        },
        required: ['name', 'action'],
        additionalProperties: false,
      },
      output: {
        schema: { type: 'object', properties: {}, additionalProperties: true },
        render: (_args, value) => textResult(value),
      },
      timeoutMs: 120_000,
      async execute(args, exec) {
        const name = args?.name
        const action = args?.action
        if (typeof name !== 'string' || !name) {
          throw new EngineFailure('E_INVALID_PARAMS', 'name must be a non-empty string')
        }
        if (action !== 'disable' && action !== 'enable') {
          throw new EngineFailure('E_INVALID_PARAMS', 'action must be disable or enable')
        }

        const plan = await client.request(
          'create_startup_plan',
          { name, action, ...(args?.scope ? { scope: args.scope } : {}) },
          { signal: exec.signal, timeoutMs: 40_000 },
        )
        const item = plan.items?.[0] ?? {}
        const decision = await askForConfirmation(ctx, exec, {
          id: 'diskguardian-confirm-startup',
          header: action === 'disable' ? 'DiskGuardian 禁用启动项' : 'DiskGuardian 恢复启动项',
          question:
            action === 'disable'
              ? `计划 ${plan.plan_id}：禁用启动项「${name}」。原值会被保存，可随时恢复。`
              : `计划 ${plan.plan_id}：恢复启动项「${name}」到原位置。`,
          detail: `${item.target ?? name}\n${item.value_data ?? ''}`,
          confirmLabel: action === 'disable' ? '确认禁用' : '确认恢复',
          cancelLabel: '取消',
          confirmDescription: '应用这次变更',
          cancelDescription: '不执行，保持现状',
        })
        if (!decision.confirmed) {
          return { executed: false, plan_id: plan.plan_id, declined: true, reason: decision.reason, note: 'Nothing changed.' }
        }

        const issued = await client.request(
          'issue_approval',
          { plan_id: plan.plan_id, source: 'harness-user-question' },
          { signal: exec.signal, timeoutMs: 40_000 },
        )
        return client.request(
          'execute_startup_plan',
          { plan_id: plan.plan_id, approval_id: issued.approval_id },
          { signal: exec.signal, timeoutMs: 90_000 },
        )
      },
    }),
  )

  ctx.effect(() =>
    ctx.tools.register({
      name: 'list_startup_changes',
      description:
        'Read-only. List startup entries DiskGuardian disabled, with the stored original value, plan, time, and whether they were restored. Use it before re-enabling an entry or when the user asks what was disabled.',
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
      execute: (args, exec) => client.request('list_startup_changes', args ?? {}, { signal: exec.signal, timeoutMs: 40_000 }),
    }),
  )
}
