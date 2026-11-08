/**
 * Shared confirmation UI for consequential operations.
 *
 * The confirmation is performed inside the tool call through the Harness
 * user-question service, so a model reply can never stand in for a human
 * decision.
 */

import { EngineFailure } from '../engine/client.js'

const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000

/** @param {number | null | undefined} bytes */
export function formatBytes(bytes) {
  if (!bytes) return '0 B'
  const units = ['B', 'KiB', 'MiB', 'GiB']
  let value = Number(bytes)
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`
}

/**
 * @param {any} ctx
 * @param {{ agent?: any, signal?: AbortSignal }} exec
 * @param {{
 *   id: string,
 *   header: string,
 *   question: string,
 *   detail?: string,
 *   confirmLabel?: string,
 *   cancelLabel?: string,
 *   confirmDescription?: string,
 *   cancelDescription?: string,
 * }} request
 * @returns {Promise<{ confirmed: boolean, reason: string | null }>}
 */
export async function askForConfirmation(ctx, exec, request) {
  const userQuestions = ctx.get('userQuestions')
  if (!userQuestions) {
    throw new EngineFailure('E_CONFIRMATION_UNAVAILABLE', 'the user-question service is unavailable')
  }
  const confirmLabel = request.confirmLabel ?? '确认执行'
  const cancelLabel = request.cancelLabel ?? '取消'

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS)
  try {
    const answer = await userQuestions.ask({
      questions: [
        {
          id: request.id,
          header: request.header,
          question: request.question,
          detail: request.detail || undefined,
          options: [
            { label: confirmLabel, description: request.confirmDescription },
            { label: cancelLabel, description: request.cancelDescription },
          ],
          intent: { kind: 'approval', approve: confirmLabel, reject: cancelLabel },
        },
      ],
      agent: exec.agent,
      signal: controller.signal,
    })
    const selected = answer?.answers?.find((item) => item.id === request.id)?.selected ?? []
    if (selected.includes(confirmLabel)) return { confirmed: true, reason: null }
    return { confirmed: false, reason: 'the user declined' }
  } catch (error) {
    return {
      confirmed: false,
      reason: `confirmation was not obtained: ${error instanceof Error ? error.message : String(error)}`,
    }
  } finally {
    clearTimeout(timer)
  }
}
