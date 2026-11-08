/**
 * Software removal: plan with the vendor uninstaller, confirm, run, verify.
 *
 * The engine refuses interpreters and temporary-directory executables, never
 * elevates, and requires a one-time approval bound to the plan. This layer only
 * collects the confirmation from the human.
 */

import { EngineFailure } from '../engine/client.js'
import { askForConfirmation } from './confirm.js'
import { textResult } from './disk.js'

/**
 * @param {{ ctx: any, client: import('../engine/client.js').EngineClient }} deps
 */
export function registerRemovalTools({ ctx, client }) {
  ctx.effect(() =>
    ctx.tools.register({
      name: 'create_removal_plan',
      description:
        'Read-only planning. Build a removal plan for named software using the vendor uninstall command from the registry. The engine validates the uninstaller (local .exe, never an interpreter, never a temp/download path) and refuses when the target is ambiguous. Nothing is uninstalled until a separate confirmed execution.',
      parameters: {
        type: 'object',
        properties: {
          software: {
            type: 'array',
            items: {
              oneOf: [
                { type: 'string' },
                {
                  type: 'object',
                  properties: {
                    name: { type: 'string' },
                    publisher: { type: 'string' },
                    version: { type: 'string' },
                  },
                  required: ['name'],
                  additionalProperties: false,
                },
              ],
            },
          },
        },
        required: ['software'],
        additionalProperties: false,
      },
      output: {
        schema: { type: 'object', properties: {}, additionalProperties: true },
        render: (_args, value) => textResult(value),
      },
      timeoutMs: 90_000,
      execute: (args, exec) => client.request('create_removal_plan', args ?? {}, { signal: exec.signal, timeoutMs: 70_000 }),
    }),
  )

  ctx.effect(() =>
    ctx.tools.register({
      name: 'execute_removal_plan',
      description:
        'Side effect. Run the vendor uninstaller for a removal plan. This tool asks the human to confirm each plan through the Harness confirmation UI; the model cannot approve. No elevation is attempted — if Windows requires administrator rights, the result says so. Removal is not quarantined: files are removed by the vendor uninstaller and cannot be restored by DiskGuardian.',
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
      timeoutMs: 900_000,
      async execute(args, exec) {
        const planId = args?.plan_id
        if (typeof planId !== 'string' || !planId) {
          throw new EngineFailure('E_INVALID_PARAMS', 'plan_id must be a non-empty string')
        }
        const plan = await client.request('preview_action_plan', { plan_id: planId }, { signal: exec.signal, timeoutMs: 40_000 })
        if (plan.expired) {
          throw new EngineFailure('E_PLAN_EXPIRED', 'the plan expired; create a new removal plan')
        }
        if (plan.status !== 'pending') {
          throw new EngineFailure('E_INVALID_STATE', `the plan state is ${plan.status}, not pending`)
        }
        if (plan.plan_type !== 'removal') {
          throw new EngineFailure('E_INVALID_PARAMS', 'this plan is not a removal plan')
        }

        const software = (plan.items ?? []).map((item) => `${item.software} ${item.version ?? ''}`.trim())
        const decision = await askForConfirmation(ctx, exec, {
          id: 'diskguardian-confirm-removal',
          header: 'DiskGuardian 卸载确认',
          question: `计划 ${planId}：卸载 ${software.length} 个软件。将调用各自厂商的卸载程序，无法由 DiskGuardian 恢复。`,
          detail: software.map((name, index) => `${index + 1}. ${name}`).join('\n'),
          confirmLabel: '确认卸载',
          cancelLabel: '取消',
          confirmDescription: '运行厂商卸载程序',
          cancelDescription: '不执行，不修改任何软件',
        })
        if (!decision.confirmed) {
          return { executed: false, plan_id: planId, declined: true, reason: decision.reason, note: 'No software was removed.' }
        }

        const issued = await client.request(
          'issue_approval',
          { plan_id: planId, source: 'harness-user-question' },
          { signal: exec.signal, timeoutMs: 40_000 },
        )
        return client.request(
          'execute_removal_plan',
          { plan_id: planId, approval_id: issued.approval_id },
          { signal: exec.signal, timeoutMs: 870_000 },
        )
      },
    }),
  )

  ctx.effect(() =>
    ctx.tools.register({
      name: 'inspect_removal_residue',
      description:
        'Read-only. After an uninstall, check whether the software is still registered and measure leftover directories you name (install location and/or candidate paths). It never deletes residue: leftovers under Program Files, ProgramData, or the registry are not eligible for automatic cleanup.',
      parameters: {
        type: 'object',
        properties: {
          software: { type: 'string'},
          install_location: { type: 'string' },
          candidate_paths: { type: 'array', items: { type: 'string' }},
        },
        required: ['software'],
        additionalProperties: false,
      },
      output: {
        schema: { type: 'object', properties: {}, additionalProperties: true },
        render: (_args, value) => textResult(value),
      },
      timeoutMs: 90_000,
      execute: (args, exec) => client.request('inspect_removal_residue', args ?? {}, { signal: exec.signal, timeoutMs: 70_000 }),
    }),
  )
}
