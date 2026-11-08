/**
 * Evidence-first analyzers. Each tool scans its own data through the engine and
 * returns findings with risk level, confidence, evidence, and a recommended
 * action. None of them changes anything.
 */

import { textResult } from './disk.js'

/**
 * @param {any} ctx
 * @param {import('../engine/client.js').EngineClient} client
 * @param {{ name: string, description: string, parameters: Record<string, unknown>, timeoutMs: number }} spec
 */
function defineAnalyzer(ctx, client, spec) {
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
        client.request(spec.name, args ?? {}, { signal: exec.signal, timeoutMs: spec.timeoutMs - 5_000 }),
    }),
  )
}

/**
 * @param {{ ctx: any, client: import('../engine/client.js').EngineClient }} deps
 */
export function registerAnalyzerTools({ ctx, client }) {
  defineAnalyzer(ctx, client, {
    name: 'analyze_software',
    description:
      'Read-only. Assess installed software for trust signals: signature result, publisher, install location, uninstall metadata. Returns findings with risk level, confidence, evidence, and a recommended action. It never returns a malware verdict — this build has no threat-intelligence feed, so "suspicious" means "verify this", not "this is malware".',
    parameters: {
      type: 'object',
      properties: {
        include_signature: { type: 'boolean', default: true },
        limit: { type: 'integer', default: 300 },
      },
      additionalProperties: false,
    },
    timeoutMs: 180_000,
  })

  defineAnalyzer(ctx, client, {
    name: 'analyze_startup',
    description:
      'Read-only. Assess startup entries: missing executables, unsigned binaries, user-writable locations, and command-interpreter launchers. Returns evidence and a recommended action per entry. Structural signals are questions to verify, not proof of intent.',
    parameters: {
      type: 'object',
      properties: {
        include_signature: { type: 'boolean', default: true },
        include_tasks: { type: 'boolean', default: true },
      },
      additionalProperties: false,
    },
    timeoutMs: 180_000,
  })

  defineAnalyzer(ctx, client, {
    name: 'analyze_browser',
    description:
      'Read-only. Assess Chrome and Edge extensions (side-loaded, all-site access, high-impact permissions) and settings (unknown default search provider). Always reports whether machine policy is present, so a managed setting is not mistaken for hijacking.',
    parameters: { type: 'object', properties: {}, additionalProperties: false },
    timeoutMs: 180_000,
  })

  defineAnalyzer(ctx, client, {
    name: 'analyze_security_status',
    description:
      'Read-only. Assess Windows security posture: Defender state, definition age, firewall profiles, security services, and Windows lifecycle. Returns findings with severity, evidence, and the action a user should take. It never disables anything.',
    parameters: { type: 'object', properties: {}, additionalProperties: false },
    timeoutMs: 120_000,
  })
}
