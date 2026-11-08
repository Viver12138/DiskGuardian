/**
 * Disk inspection tools (read-only, L0).
 *
 * Every tool is a fixed engine operation plus a bounded parameter object. None
 * of them deletes, moves, or writes anything; cleanup plans arrive in Phase D
 * with their own permission gates.
 */

/** @param {unknown} value */
export function textResult(value) {
  return [{ type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value, null, 2) }];
}

/**
 * @param {{ ctx: any, client: import('../engine/client.js').EngineClient }} deps
 */
export function registerDiskTools({ ctx, client }) {
  ctx.effect(() =>
    ctx.tools.register({
      name: 'scan_disk',
      description:
        'Read-only. Report local fixed disks: total, used, and free bytes plus used ratio. Use it to ground any storage recommendation in real numbers before proposing cleanup.',
      parameters: { type: 'object', properties: {}, additionalProperties: false },
      output: {
        schema: {
          type: 'object',
          properties: {
            disks: { type: 'array', items: { type: 'object', additionalProperties: true } },
            skipped: { type: 'array', items: { type: 'object', additionalProperties: true } },
            scan_id: { type: 'string' },
            storage_error: { type: 'string' },
          },
          required: ['disks'],
          additionalProperties: true,
        },
        render: (_args, value) => textResult(value),
      },
      timeoutMs: 30_000,
      execute: (_args, exec) => client.request('scan_disk', {}, { signal: exec.signal, timeoutMs: 20_000 }),
    }),
  );

  ctx.effect(() =>
    ctx.tools.register({
      name: 'scan_directories',
      description:
        'Read-only. Measure directory size within local fixed disks only. Defaults to the user temp, Windows temp, and LocalAppData directories. Returns per-path totals and the largest direct children. Reparse points are skipped, and the walk stops at an entry/time budget which the result reports.',
      parameters: {
        type: 'object',
        properties: {
          paths: {
            type: 'array',
            items: { type: 'string' },
            description: 'Absolute local paths. Network paths and non-fixed drives are rejected.',
          },
          max_depth: { type: 'integer', default: 2 },
          max_entries: { type: 'integer'},
          max_seconds: { type: 'integer'},
        },
        additionalProperties: false,
      },
      output: {
        schema: {
          type: 'object',
          properties: {
            analysis: { type: 'array', items: { type: 'object', additionalProperties: true } },
            entries_examined: { type: 'integer' },
            truncated: { type: 'boolean' },
            scan_id: { type: 'string' },
            storage_error: { type: 'string' },
          },
          required: ['analysis'],
          additionalProperties: true,
        },
        render: (_args, value) => textResult(value),
      },
      timeoutMs: 120_000,
      execute: (args, exec) => client.request('scan_directories', args ?? {}, { signal: exec.signal, timeoutMs: 110_000 }),
    }),
  );

  ctx.effect(() =>
    ctx.tools.register({
      name: 'find_large_files',
      description:
        'Read-only. Find the largest files under the given roots on local fixed disks. Defaults to the user profile and 100 MiB minimum size. Returns size, modification time, and whether a file carries the system attribute; it never classifies a file as deletable.',
      parameters: {
        type: 'object',
        properties: {
          roots: { type: 'array', items: { type: 'string' }},
          min_bytes: { type: 'integer', default: 104857600 },
          limit: { type: 'integer', default: 50 },
          max_entries: { type: 'integer'},
          max_seconds: { type: 'integer'},
        },
        additionalProperties: false,
      },
      output: {
        schema: {
          type: 'object',
          properties: {
            files: { type: 'array', items: { type: 'object', additionalProperties: true } },
            files_scanned: { type: 'integer' },
            min_bytes: { type: 'integer' },
            limit: { type: 'integer' },
            truncated: { type: 'boolean' },
            scan_id: { type: 'string' },
            storage_error: { type: 'string' },
          },
          required: ['files'],
          additionalProperties: true,
        },
        render: (_args, value) => textResult(value),
      },
      timeoutMs: 120_000,
      execute: (args, exec) => client.request('find_large_files', args ?? {}, { signal: exec.signal, timeoutMs: 110_000 }),
    }),
  );
}
