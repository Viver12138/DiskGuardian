import assert from 'node:assert/strict'
import test from 'node:test'

/**
 * The tools close over the client created inside `apply`, so these tests call
 * each registration function directly with a fake client and a fake Host
 * context. That keeps the confirmation logic under test without a live Host.
 */
async function registered(decide, responses) {
  const calls = []
  const tools = new Map()
  const ctx = {
    effect: (factory) => factory(),
    get: (name) =>
      name === 'userQuestions'
        ? {
            async ask(request) {
              const question = request.questions[0]
              const selected = decide(question)
              if (selected instanceof Error) throw selected
              return { answers: [{ id: question.id, selected: Array.isArray(selected) ? selected : [selected] }] }
            },
          }
        : undefined,
    tools: {
      register(definition) {
        tools.set(definition.name, definition)
        return () => {}
      },
    },
    systemPrompt: { section: () => () => {} },
  }
  const client = {
    async request(operation, params) {
      calls.push({ operation, params })
      const responder = responses[operation]
      if (responder === undefined) throw new Error(`unexpected engine call: ${operation}`)
      return typeof responder === 'function' ? responder(params, calls) : responder
    },
  }
  const { registerCleanupTools } = await import('../src/tools/cleanup.js')
  const { registerRemovalTools } = await import('../src/tools/removal.js')
  const { registerStartupTools } = await import('../src/tools/startup.js')
  registerCleanupTools({ ctx, client })
  registerRemovalTools({ ctx, client })
  registerStartupTools({ ctx, client })
  return { tools, calls }
}

const PENDING_CLEANUP_PLAN = {
  plan_id: 'plan_cleanup',
  plan_type: 'cleanup',
  status: 'pending',
  expired: false,
  items: [{ target: 'C:\\Temp\\a.tmp', size_bytes: 10 }],
  reversible: true,
}

test('cleanup asks the human, then issues one approval and executes', async () => {
  const { tools, calls } = await registered(
    () => '确认执行',
    {
      preview_action_plan: PENDING_CLEANUP_PLAN,
      issue_approval: { approval_id: 'approval_1' },
      execute_cleanup_plan: { success: true, status: 'completed' },
    },
  )
  const tool = tools.get('execute_cleanup_plan')
  const result = await tool.execute({ plan_id: 'plan_cleanup' }, { agent: { id: 'session_1' } })

  assert.deepEqual(
    calls.map((call) => call.operation),
    ['preview_action_plan', 'issue_approval', 'execute_cleanup_plan'],
  )
  assert.equal(calls[1].params.plan_id, 'plan_cleanup')
  assert.equal(calls[1].params.source, 'harness-user-question')
  assert.equal(calls[2].params.approval_id, 'approval_1')
  assert.equal(result.success, true)
})

test('declining cleanup changes nothing', async () => {
  const { tools, calls } = await registered(
    () => '取消',
    { preview_action_plan: PENDING_CLEANUP_PLAN },
  )
  const result = await tools.get('execute_cleanup_plan').execute({ plan_id: 'plan_cleanup' }, {})
  assert.equal(result.declined, true)
  assert.deepEqual(
    calls.map((call) => call.operation),
    ['preview_action_plan'],
  )
})

test('a confirmation service error is reported as declined, not as success', async () => {
  const { tools } = await registered(
    () => new Error('answerer unavailable'),
    { preview_action_plan: PENDING_CLEANUP_PLAN },
  )
  const result = await tools.get('execute_cleanup_plan').execute({ plan_id: 'plan_cleanup' }, {})
  assert.equal(result.declined, true)
  assert.match(result.reason, /confirmation was not obtained/)
})

test('a removal plan cannot be executed as a cleanup plan', async () => {
  const { tools } = await registered(
    () => '确认执行',
    { preview_action_plan: { ...PENDING_CLEANUP_PLAN, plan_type: 'removal' } },
  )
  await assert.rejects(
    () => tools.get('execute_cleanup_plan').execute({ plan_id: 'plan_removal' }, {}),
    (error) => error.code === 'E_INVALID_PARAMS',
  )
})

test('an expired plan is refused before asking the human', async () => {
  let asked = false
  const { tools } = await registered(
    () => {
      asked = true
      return '确认执行'
    },
    { preview_action_plan: { ...PENDING_CLEANUP_PLAN, expired: true } },
  )
  await assert.rejects(
    () => tools.get('execute_cleanup_plan').execute({ plan_id: 'plan_cleanup' }, {}),
    (error) => error.code === 'E_PLAN_EXPIRED',
  )
  assert.equal(asked, false)
})

test('removal asks for a separate confirmation and passes the plan id', async () => {
  const { tools, calls } = await registered(
    () => '确认卸载',
    {
      preview_action_plan: {
        plan_id: 'plan_removal',
        plan_type: 'removal',
        status: 'pending',
        expired: false,
        items: [{ software: 'Example', version: '1.0' }],
      },
      issue_approval: { approval_id: 'approval_2' },
      execute_removal_plan: { success: true },
    },
  )
  const result = await tools.get('execute_removal_plan').execute({ plan_id: 'plan_removal' }, {})
  assert.equal(result.success, true)
  assert.equal(calls.at(-1).operation, 'execute_removal_plan')
  assert.equal(calls.at(-1).params.approval_id, 'approval_2')
})

test('startup management plans, confirms, and executes one reversible change', async () => {
  const { tools, calls } = await registered(
    () => '确认禁用',
    {
      create_startup_plan: {
        plan_id: 'plan_startup',
        items: [{ target: 'HKCU\\...\\Run\\OneDrive', value_data: 'C:\\...\\OneDrive.exe' }],
      },
      issue_approval: { approval_id: 'approval_3' },
      execute_startup_plan: { success: true, affected_items: [{ state: 'disabled' }] },
    },
  )
  const result = await tools.get('manage_startup_entry').execute({ name: 'OneDrive', action: 'disable' }, {})
  assert.equal(result.success, true)
  assert.equal(calls[0].operation, 'create_startup_plan')
  assert.equal(calls[0].params.action, 'disable')
  assert.equal(calls.at(-1).params.approval_id, 'approval_3')
})

test('purge previews, then asks, then deletes only after confirmation', async () => {
  const { tools, calls } = await registered(
    () => '永久删除',
    {
      purge_quarantine: (params) =>
        params.dry_run
          ? { dry_run: true, count: 2, bytes: 300, items: [{ original_path: 'C:\\Temp\\a', bytes: 150 }] }
          : { dry_run: false, purged: 2, bytes_freed: 300 },
    },
  )
  const result = await tools.get('purge_quarantine').execute({ all: true }, {})
  assert.equal(result.purged, 2)
  assert.deepEqual(calls.map((call) => call.operation), ['purge_quarantine', 'purge_quarantine'])
  assert.equal(calls[0].params.dry_run, true)
  assert.equal(calls[1].params.dry_run, undefined)
})

test('declining purge deletes nothing', async () => {
  const { tools, calls } = await registered(
    () => '取消',
    { purge_quarantine: { dry_run: true, count: 1, bytes: 10, items: [] } },
  )
  const result = await tools.get('purge_quarantine').execute({ all: true }, {})
  assert.equal(result.declined, true)
  assert.equal(calls.length, 1)
  assert.equal(calls[0].params.dry_run, true)
})

test('purge refuses to run without a filter', async () => {
  const { tools, calls } = await registered(() => '永久删除', {})
  await assert.rejects(
    () => tools.get('purge_quarantine').execute({}, {}),
    (error) => error.code === 'E_INVALID_PARAMS',
  )
  assert.equal(calls.length, 0)
})

test('execute tools expose no way for the model to supply an approval', async () => {
  const { tools } = await registered(() => '取消', {})
  for (const name of ['execute_cleanup_plan', 'execute_removal_plan', 'manage_startup_entry']) {
    const schema = tools.get(name).parameters
    assert.ok(!('approval_id' in (schema.properties ?? {})), `${name} must not accept approval_id`)
    assert.ok(!('approved' in (schema.properties ?? {})), `${name} must not accept an approved flag`)
  }
})
