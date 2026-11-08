import assert from 'node:assert/strict'
import { PassThrough } from 'node:stream'
import test from 'node:test'

import { EngineClient, EngineFailure } from '../src/engine/client.js'

/**
 * Build a fake `ctx.subprocess` that answers like the Python engine.
 * `responder` returns an envelope object, `null` for "no output", or 'hang'.
 */
function fakeSubprocess(responder, { spawnThrows = false } = {}) {
  const requests = []
  const subprocess = {
    async resolveExecutable(command) {
      return `C:\\fake\\${command}.exe`
    },
    spawn(spec) {
      if (spawnThrows) throw new Error('spawn blocked')
      assert.equal(spec.argv[0], 'C:\\fake\\python.exe')
      assert.ok(spec.argv.includes('-I'))
      assert.ok(spec.argv.at(-1).endsWith('run.py'))
      // The client must send the request as one-shot stdin data, not by racing
      // writes against the process start.
      assert.equal(typeof spec.stdio.stdin, 'object')
      assert.equal(typeof spec.stdio.stdin.data, 'string')
      const stdin = new PassThrough()
      const stdout = new PassThrough()
      const stderr = new PassThrough()
      let settle
      const done = new Promise((resolve) => {
        settle = resolve
      })
      const respondTo = (line) => {
        const request = JSON.parse(line)
        requests.push(request)
        const reply = responder(request)
        if (reply === null) {
          settle({ exitCode: 1, signal: null })
          stdout.end()
          return
        }
        if (reply === 'hang') return
        stdout.end(`${JSON.stringify(reply)}\n`, () => settle({ exitCode: 0, signal: null }))
      }
      const line = spec.stdio.stdin.data.split('\n').find((candidate) => candidate.trim().length > 0) ?? ''
      queueMicrotask(() => respondTo(line))
      return {
        stdin,
        stdout,
        stderr,
        done,
        terminate() {
          stdout.end()
          settle({ exitCode: null, signal: 'SIGTERM' })
        },
      }
    },
  }
  const ctx = { get: (name) => (name === 'subprocess' ? subprocess : undefined) }
  return { ctx, requests }
}

function clientFor(responder, options) {
  const { ctx, requests } = fakeSubprocess(responder, options)
  const client = new EngineClient({ ctx, engineDir: 'C:\\bundle\\engine' })
  return { client, requests }
}

test('returns the data of a successful envelope', async () => {
  const { client } = clientFor((request) => ({
    request_id: request.request_id,
    success: true,
    data: { disks: [{ root: 'C:\\' }] },
    error: null,
  }))
  const data = await client.request('scan_disk', {}, { timeoutMs: 2_000 })
  assert.deepEqual(data, { disks: [{ root: 'C:\\' }] })
})

test('sends one fixed operation with structured params', async () => {
  const { client, requests } = clientFor((request) => ({
    request_id: request.request_id,
    success: true,
    data: {},
    error: null,
  }))
  await client.request('find_large_files', { min_bytes: 2048 })
  assert.equal(requests.length, 1)
  assert.equal(requests[0].operation, 'find_large_files')
  assert.deepEqual(requests[0].params, { min_bytes: 2048 })
})

test('maps an engine error envelope onto EngineFailure', async () => {
  const { client } = clientFor((request) => ({
    request_id: request.request_id,
    success: false,
    data: null,
    error: { code: 'E_PATH_NOT_ALLOWED', message: 'network paths are not scanned' },
  }))
  await assert.rejects(
    () => client.request('scan_directories', { paths: ['\\\\server\\share'] }),
    (error) => {
      assert.ok(error instanceof EngineFailure)
      assert.equal(error.code, 'E_PATH_NOT_ALLOWED')
      return true
    },
  )
})

test('rejects a response that never arrives', async () => {
  const { client } = clientFor(() => null)
  await assert.rejects(
    () => client.request('scan_disk'),
    (error) => error.code === 'E_ENGINE_PROTOCOL',
  )
})

test('terminates the engine on timeout', async () => {
  const { client } = clientFor(() => 'hang')
  await assert.rejects(
    () => client.request('scan_disk', {}, { timeoutMs: 25 }),
    (error) => error.code === 'E_TIMEOUT',
  )
})

test('reports a blocked spawn instead of throwing raw errors', async () => {
  const { client } = clientFor(() => 'hang', { spawnThrows: true })
  await assert.rejects(
    () => client.request('scan_disk'),
    (error) => error.code === 'E_ENGINE_SPAWN',
  )
})

test('reads collect-mode output when the provider exposes no stdout stream', async () => {
  const { PassThrough } = await import('node:stream')
  let stdoutText = ''
  const handle = {
    stdin: new PassThrough(),
    stdout: undefined,
    stderr: undefined,
    collected: {
      stdout: { readFrom: () => ({ text: stdoutText, nextOffset: stdoutText.length, lossy: false }) },
      stderr: { readFrom: () => ({ text: '', nextOffset: 0, lossy: false }) },
    },
    done: Promise.resolve({ exitCode: 0, signal: null }),
    terminate() {},
  }
  const ctx = {
    get: (name) =>
      name === 'subprocess'
        ? {
            async resolveExecutable() {
              return 'C:\\fake\\python.exe'
            },
            spawn(spec) {
              const line = spec.stdio.stdin.data.split('\n').find((candidate) => candidate.trim().length > 0) ?? ''
              const request = JSON.parse(line)
              stdoutText = `${JSON.stringify({ request_id: request.request_id, success: true, data: { via: 'collect' }, error: null })}\n`
              return handle
            },
          }
        : undefined,
  }
  const client = new EngineClient({ ctx, engineDir: 'C:\\bundle\\engine' })
  const data = await client.request('scan_disk', {}, { timeoutMs: 2_000 })
  assert.deepEqual(data, { via: 'collect' })
})

test('reports observed byte counts when the engine answers with nothing', async () => {
  const { client } = clientFor(() => null)
  await assert.rejects(
    () => client.request('scan_disk'),
    (error) => error.code === 'E_ENGINE_PROTOCOL' && /stdout 0 bytes/.test(error.message),
  )
})

test('refuses an oversized request before spawning', async () => {
  const { client, requests } = clientFor((request) => ({
    request_id: request.request_id,
    success: true,
    data: {},
    error: null,
  }))
  await assert.rejects(
    () => client.request('scan_directories', { paths: ['x'.repeat(1024 * 1024)] }),
    (error) => error.code === 'E_TOO_LARGE',
  )
  assert.equal(requests.length, 0)
})
