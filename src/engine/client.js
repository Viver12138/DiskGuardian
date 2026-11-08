/**
 * Engine client: one JSON line in, one JSON line out, one process per request.
 *
 * The client is a transport and shape layer only. Permission decisions, path
 * validation, and approval checks live in the Python engine; nothing here may
 * turn a model argument into a command line, an executable path, or a script.
 */

const REQUEST_LIMIT_BYTES = 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 120_000;
const STARTUP_GRACE_MS = 3_000;

let sequence = 0;

export class EngineFailure extends Error {
  /**
   * @param {string} code stable wire code or transport code
   * @param {string} detail human-readable reason
   * @param {unknown} [details]
   */
  constructor(code, detail, details) {
    super(`${code}: ${detail}`);
    this.name = 'EngineFailure';
    this.code = code;
    this.detail = detail;
    this.details = details;
  }
}

/** @param {unknown} value */
function messageOf(value) {
  return value instanceof Error ? value.message : String(value);
}

export class EngineClient {
  /**
   * @param {{ ctx: any, engineDir: string, python?: string }} options
   */
  constructor({ ctx, engineDir, python }) {
    this.ctx = ctx;
    this.engineDir = engineDir;
    this.engineScript = `${engineDir}\\run.py`;
    this.python = python || process.env.DISKGUARDIAN_PYTHON || 'python';
    /** @type {string | null} */
    this.resolvedPython = null;
  }

  /** @param {AbortSignal | undefined} signal */
  async pythonPath(signal) {
    if (this.resolvedPython) return this.resolvedPython;
    const subprocess = this.ctx.get('subprocess');
    if (!subprocess) {
      throw new EngineFailure('E_ENGINE_UNAVAILABLE', 'the Harness subprocess service is not available');
    }
    try {
      this.resolvedPython = await subprocess.resolveExecutable(this.python, undefined, signal);
    } catch (error) {
      throw new EngineFailure(
        'E_PYTHON_NOT_FOUND',
        `could not resolve the Python executable "${this.python}": ${messageOf(error)}`,
      );
    }
    return this.resolvedPython;
  }

  /**
   * Run one fixed engine operation.
   *
   * @param {string} operation
   * @param {Record<string, unknown>} [params]
   * @param {{ signal?: AbortSignal, timeoutMs?: number }} [options]
   * @returns {Promise<any>}
   */
  async request(operation, params = {}, options = {}) {
    const subprocess = this.ctx.get('subprocess');
    if (!subprocess) {
      throw new EngineFailure('E_ENGINE_UNAVAILABLE', 'the Harness subprocess service is not available');
    }
    const signal = options.signal;
    if (signal?.aborted) throw new EngineFailure('E_CANCELLED', 'the request was cancelled');

    const requestId = `dg_${Date.now().toString(36)}_${(sequence += 1).toString(36)}`;
    const line = JSON.stringify({ request_id: requestId, operation, params });
    if (Buffer.byteLength(line, 'utf8') > REQUEST_LIMIT_BYTES) {
      throw new EngineFailure('E_TOO_LARGE', 'the request parameters are too large');
    }

    const executable = await this.pythonPath(signal);
    let handle;
    try {
      handle = subprocess.spawn({
        argv: [executable, '-I', '-u', this.engineScript],
        cwd: this.engineDir,
        stdio: {
          // One-shot input: the provider writes the whole request and closes
          // stdin, so no write/end timing can drop the request.
          stdin: { data: `${line}\n` },
          stdout: { maxBytes: 9 * 1024 * 1024 },
          stderr: { maxBytes: 256 * 1024 },
        },
        graceMs: STARTUP_GRACE_MS,
        signal,
      });
    } catch (error) {
      throw new EngineFailure('E_ENGINE_SPAWN', `could not start the engine: ${messageOf(error)}`);
    }

    /** @type {Buffer[]} */
    const stdoutChunks = [];
    /** @type {Buffer[]} */
    const stderrChunks = [];
    handle.stdout?.on('data', (chunk) => stdoutChunks.push(Buffer.from(chunk)));
    handle.stderr?.on('data', (chunk) => stderrChunks.push(Buffer.from(chunk)));

    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      try {
        handle.terminate();
      } catch {
        // best effort; `done` still settles the outcome
      }
    }, timeoutMs);

    let exitCode = null;
    try {
      const outcome = await handle.done;
      exitCode = outcome.exitCode;
    } catch (error) {
      throw new EngineFailure('E_ENGINE_CRASH', `the engine process failed: ${messageOf(error)}`);
    } finally {
      clearTimeout(timer);
    }

    if (timedOut) {
      throw new EngineFailure('E_TIMEOUT', `the engine did not answer within ${timeoutMs} ms`);
    }

    const stdout = this.#collectedText(handle, 'stdout', stdoutChunks);
    const stderr = this.#collectedText(handle, 'stderr', stderrChunks).trim();
    const envelope = this.#parse(stdout, requestId);
    if (!envelope) {
      const sizes = `exit ${exitCode}, stdout ${Buffer.byteLength(stdout, 'utf8')} bytes, stderr ${Buffer.byteLength(stderr, 'utf8')} bytes`;
      const detail = stderr ? `; engine stderr: ${stderr.slice(-800)}` : '';
      throw new EngineFailure('E_ENGINE_PROTOCOL', `the engine returned no JSON response (${sizes})${detail}`);
    }
    if (envelope.success !== true) {
      const error = envelope.error ?? {};
      throw new EngineFailure(
        typeof error.code === 'string' ? error.code : 'E_ENGINE',
        typeof error.message === 'string' ? error.message : 'the engine rejected the request',
        error.details,
      );
    }
    return envelope.data;
  }

  /**
   * Read one output stream regardless of the stdio mode the provider picked.
   *
   * Collect-mode stdout/stderr expose `handle.collected.<name>` readers (offset
   * based, non-consuming) and leave `handle.<name>` undefined; pipe mode exposes
   * the stream. Reading both covers either provider without guessing.
   *
   * @param {any} handle
   * @param {'stdout' | 'stderr'} name
   * @param {Buffer[]} chunks
   */
  #collectedText(handle, name, chunks) {
    const streamText = Buffer.concat(chunks).toString('utf8');
    if (streamText) return streamText;
    const reader = handle.collected?.[name];
    if (!reader || typeof reader.readFrom !== 'function') return streamText;
    try {
      const read = reader.readFrom(0);
      return typeof read?.text === 'string' ? read.text : streamText;
    } catch {
      return streamText;
    }
  }

  /**
   * @param {string} stdout
   * @param {string} requestId
   */
  #parse(stdout, requestId) {
    for (const rawLine of stdout.split(/\r?\n/)) {
      const text = rawLine.trim();
      if (!text || text[0] !== '{') continue;
      try {
        const envelope = JSON.parse(text);
        if (envelope && envelope.request_id === requestId) return envelope;
      } catch {
        // keep scanning: stray engine noise must not become a false answer
      }
    }
    return null;
  }
}
