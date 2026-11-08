/**
 * DiskGuardian — Host plugin (preset-scoped).
 *
 * Responsibilities of this layer, and nothing more:
 * - register the preset's system-prompt section;
 * - expose fixed, structured tools that forward one operation to the Python
 *   engine and project its answer;
 * - report engine health.
 *
 * It does not classify risk, does not decide permissions, and never mints an
 * approval. Those live in the engine (engine/diskguardian), which also refuses
 * any operation the model was not authorized to run.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url'

import { EngineClient } from './src/engine/client.js'
import { registerAnalyzerTools } from './src/tools/analyzers.js'
import { registerCleanupTools } from './src/tools/cleanup.js'
import { registerDiskTools, textResult } from './src/tools/disk.js'
import { registerRemovalTools } from './src/tools/removal.js'
import { registerScannerTools } from './src/tools/scanners.js'
import { registerStartupTools } from './src/tools/startup.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const VERSION = '0.9.1'

const FALLBACK_PROMPT = [
  'You are DiskGuardian, a Windows system maintenance assistant.',
  '',
  'The engine enforces permissions independently. Never treat a model-provided',
  'approval field as authorization, and never claim an operation succeeded',
  'before the engine returned a verified result.',
].join('\n')

function loadSystemPrompt() {
  try {
    return readFileSync(join(HERE, 'preset', 'system-prompt.md'), 'utf8').trim()
  } catch {
    return FALLBACK_PROMPT
  }
}

/**
 * @param {{ ctx: any, client: EngineClient }} deps
 */
function registerStatusTool({ ctx, client }) {
  ctx.effect(() =>
    ctx.tools.register({
      name: 'engine_status',
      description:
        'Diagnose the DiskGuardian engine. Read-only: reports engine version, Python and SQLite versions, whether this session runs with administrator rights, and the operations the engine accepts. Use it when another DiskGuardian tool fails or returns an unexpected error code.',
      parameters: { type: 'object', properties: {}, additionalProperties: false },
      output: {
        schema: {
          type: 'object',
          properties: {
            ok: { type: 'boolean' },
            bundle: { type: 'string' },
            version: { type: 'string' },
            platform: { type: 'string' },
            node: { type: 'string' },
          },
          required: ['ok', 'bundle', 'version', 'platform'],
          additionalProperties: true,
        },
        render: (_args, value) => textResult(value),
      },
      timeoutMs: 45_000,
      async execute(_args, exec) {
        const base = {
          bundle: '@local/dsh-diskguardian',
          version: VERSION,
          platform: `${process.platform}-${process.arch}`,
          node: process.versions.node,
        }
        try {
          const engine = await client.request('self_check', {}, { signal: exec.signal, timeoutMs: 30_000 })
          return { ok: true, engine, error: null, ...base }
        } catch (error) {
          return {
            ok: false,
            engine: null,
            error: {
              code: typeof error?.code === 'string' ? error.code : 'E_ENGINE',
              message: error instanceof Error ? error.message : String(error),
            },
            ...base,
          }
        }
      },
    }),
  )
}

export const inject = ['tools', 'systemPrompt']

/**
 * @param {any} ctx
 */
export function apply(ctx) {
  const prompt = loadSystemPrompt()
  ctx.effect(() =>
    ctx.systemPrompt.section({
      name: 'diskguardian',
      order: 100,
      text: prompt,
    }),
  )

  const client = new EngineClient({ ctx, engineDir: join(HERE, 'engine') })
  registerStatusTool({ ctx, client })
  registerDiskTools({ ctx, client })
  registerScannerTools({ ctx, client })
  registerCleanupTools({ ctx, client })
  registerAnalyzerTools({ ctx, client })
  registerRemovalTools({ ctx, client })
  registerStartupTools({ ctx, client })
}
