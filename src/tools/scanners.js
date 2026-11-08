/**
 * Inventory and posture scanners (read-only, L0).
 *
 * Each tool forwards one fixed engine operation. The engine owns validation,
 * budgets, and coverage reporting; these definitions only describe the contract
 * to the model and project the answer.
 */

import { textResult } from './disk.js'

/**
 * @param {any} ctx
 * @param {import('../engine/client.js').EngineClient} client
 * @param {{
 *   name: string,
 *   description: string,
 *   parameters: Record<string, unknown>,
 *   timeoutMs: number,
 * }} spec
 */
function defineScanner(ctx, client, spec) {
  ctx.effect(() =>
    ctx.tools.register({
      name: spec.name,
      description: spec.description,
      parameters: spec.parameters,
      output: {
        schema: { type: 'object', properties: {}, additionalProperties: true },
        render: (_args, value) => textResult(value),
      },
      timeoutMs: spec.timeoutMs,
      execute: (args, exec) =>
        client.request(spec.name, args ?? {}, {
          signal: exec.signal,
          timeoutMs: spec.timeoutMs - 5_000,
        }),
    }),
  )
}

const NO_SIGNATURE = {
  type: 'boolean',
  default: false,
  description: 'Verify Authenticode signatures. Slower; a missing signature is evidence, not a verdict.',
}

/**
 * @param {{ ctx: any, client: import('../engine/client.js').EngineClient }} deps
 */
export function registerScannerTools({ ctx, client }) {
  defineScanner(ctx, client, {
    name: 'list_installed_software',
    description:
      'Read-only. List installed software from the Windows uninstall registry keys (machine 64/32-bit and per-user). Returns name, version, publisher, install location, uninstall command, and optionally an Authenticode result. System components, updates, and hotfixes are filtered out and counted in coverage. Never uninstalls anything.',
    parameters: {
      type: 'object',
      properties: {
        include_signature: NO_SIGNATURE,
        limit: { type: 'integer', default: 300 },
      },
      additionalProperties: false,
    },
    timeoutMs: 120_000,
  })

  defineScanner(ctx, client, {
    name: 'inspect_startup_entries',
    description:
      'Read-only. List startup entries: HKCU/HKLM Run and RunOnce values, user and common Startup folders, and scheduled tasks. Each entry reports its command, extracted executable, whether that file exists, its scope, and optionally its signature. This tool never disables or deletes an entry.',
    parameters: {
      type: 'object',
      properties: {
        include_signature: NO_SIGNATURE,
        include_tasks: { type: 'boolean', default: true, description: 'Include scheduled tasks.' },
      },
      additionalProperties: false,
    },
    timeoutMs: 150_000,
  })

  defineScanner(ctx, client, {
    name: 'inspect_services',
    description:
      'Read-only. List Windows services with current SCM state, start type, image path, and account. Drivers are excluded unless requested. Use it before proposing any service change; the engine still requires a reviewable plan for every change.',
    parameters: {
      type: 'object',
      properties: {
        include_signature: NO_SIGNATURE,
        running_only: { type: 'boolean', default: false },
      },
      additionalProperties: false,
    },
    timeoutMs: 120_000,
  })

  defineScanner(ctx, client, {
    name: 'inspect_browser_extensions',
    description:
      'Read-only. Inspect Chrome and Edge extension metadata (name, version, id, enabled state, permissions, install source). It never reads passwords, cookies, autofill data, history, or credentials, and it never removes an extension.',
    parameters: { type: 'object', properties: {}, additionalProperties: false },
    timeoutMs: 120_000,
  })

  defineScanner(ctx, client, {
    name: 'inspect_browser_settings',
    description:
      'Read-only. Inspect Chrome and Edge homepage, startup pages, default search provider, and whether machine policy is present. No browsing data is read. Modifying a setting or extension requires a separate confirmed plan.',
    parameters: { type: 'object', properties: {}, additionalProperties: false },
    timeoutMs: 120_000,
  })

  defineScanner(ctx, client, {
    name: 'inspect_security_status',
    description:
      'Read-only. Report Windows security posture: Defender status, firewall profile state, security service states, OS build, and support lifecycle. DiskGuardian explains and recommends; it never disables a protection feature or removes a threat itself.',
    parameters: { type: 'object', properties: {}, additionalProperties: false },
    timeoutMs: 120_000,
  })
}
