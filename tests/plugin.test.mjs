import assert from 'node:assert/strict'
import test from 'node:test'

import { apply, inject } from '../index.js'

function harness() {
  const tools = []
  const sections = []
  const ctx = {
    effect(factory) {
      return factory()
    },
    get() {
      return undefined
    },
    tools: {
      register(definition) {
        tools.push(definition)
        return () => {}
      },
    },
    systemPrompt: {
      section(section) {
        sections.push(section)
        return () => {}
      },
    },
  }
  apply(ctx)
  return { tools, sections }
}

test('registers the diskguardian prompt section', () => {
  const { sections } = harness()
  assert.equal(sections.length, 1)
  assert.equal(sections[0].name, 'diskguardian')
  assert.ok(sections[0].text.length > 200)
})

test('registers exactly the phase-E toolset', () => {
  const { tools } = harness()
  assert.deepEqual(
    tools.map((tool) => tool.name).sort(),
    [
      'analyze_browser',
      'analyze_security_status',
      'analyze_software',
      'analyze_startup',
      'classify_files',
      'create_cleanup_plan',
      'create_removal_plan',
      'engine_status',
      'execute_cleanup_plan',
      'execute_removal_plan',
      'find_large_files',
      'get_audit_log',
      'inspect_browser_extensions',
      'inspect_browser_settings',
      'inspect_removal_residue',
      'inspect_security_status',
      'inspect_services',
      'inspect_startup_entries',
      'list_cleanup_candidates',
      'list_installed_software',
      'list_quarantine',
      'list_startup_changes',
      'manage_startup_entry',
      'preview_action_plan',
      'purge_quarantine',
      'restore_quarantined_item',
      'scan_directories',
      'scan_disk',
    ],
  )
  assert.deepEqual(inject, ['tools', 'systemPrompt'])
})

test('every tool carries a usable contract', () => {
  const { tools } = harness()
  for (const tool of tools) {
    assert.equal(typeof tool.description, 'string')
    assert.ok(tool.description.length > 40, `${tool.name} needs a discoverable description`)
    assert.equal(tool.parameters.type, 'object')
    assert.equal(tool.parameters.additionalProperties, false, `${tool.name} must reject unknown parameters`)
    assert.equal(typeof tool.execute, 'function')
    assert.equal(typeof tool.timeoutMs, 'number')
    assert.ok(tool.output && typeof tool.output.render === 'function')
    assert.equal(tool.output.schema.type, 'object')
  }
})

test('render projects a structured value as one text block', () => {
  const { tools } = harness()
  const tool = tools.find((candidate) => candidate.name === 'scan_disk')
  const blocks = tool.output.render({}, { disks: [{ root: 'C:\\', used_bytes: 1 }] })
  assert.equal(blocks.length, 1)
  assert.equal(blocks[0].type, 'text')
  assert.match(blocks[0].text, /"root": "C:\\\\"/)
})

test('every schema stays inside the Host JSON-schema subset', () => {
  const { tools } = harness()
  const CONSTRAINT = new Set(['type', 'oneOf', 'properties', 'required', 'additionalProperties', 'items', 'enum', 'const'])
  const ANNOTATION = new Set(['description', 'title', 'default', 'examples'])
  const TYPES = new Set(['object', 'array', 'string', 'number', 'integer', 'boolean', 'null'])
  const ONE_OF_SIBLINGS = ['properties', 'required', 'additionalProperties', 'items', 'enum', 'const']

  const walk = (node, path) => {
    assert.ok(node && typeof node === 'object' && !Array.isArray(node), `${path} must be a schema object`)
    for (const key of Object.keys(node)) {
      assert.ok(CONSTRAINT.has(key) || ANNOTATION.has(key), `${path}.${key} is not a supported keyword`)
    }
    const hasType = 'type' in node
    const hasOneOf = 'oneOf' in node
    assert.ok(!(hasType && hasOneOf), `${path} cannot declare both type and oneOf`)
    if (hasOneOf) {
      for (const key of ONE_OF_SIBLINGS) assert.ok(!(key in node), `${path}.${key} is not supported beside oneOf`)
      assert.ok(Array.isArray(node.oneOf) && node.oneOf.length >= 2, `${path}.oneOf must hold at least two schemas`)
      node.oneOf.forEach((entry, index) => walk(entry, `${path}.oneOf[${index}]`))
      return
    }
    assert.ok(hasType, `${path} must declare type or oneOf`)
    assert.equal(typeof node.type, 'string', `${path}.type must be a single type string`)
    assert.ok(TYPES.has(node.type), `${path}.type ${node.type} is not a schema type`)
    for (const key of ['properties', 'required', 'additionalProperties']) {
      if (key in node) assert.equal(node.type, 'object', `${path}.${key} requires type object`)
    }
    if ('items' in node) assert.equal(node.type, 'array', `${path}.items requires type array`)
    for (const key of ['enum', 'const']) {
      if (key in node) assert.notEqual(node.type, 'object', `${path}.${key} is not allowed on objects`)
    }
    if (node.properties) {
      for (const [name, schema] of Object.entries(node.properties)) walk(schema, `${path}.properties.${name}`)
    }
    if (node.items) walk(node.items, `${path}.items`)
  }

  for (const tool of tools) {
    walk(tool.parameters, `${tool.name}.parameters`)
    walk(tool.output.schema, `${tool.name}.output.schema`)
  }
})

test('plugin sources never spawn processes or run commands themselves', async () => {
  const { readdir, readFile } = await import('node:fs/promises')
  const { dirname, join } = await import('node:path')
  const { fileURLToPath } = await import('node:url')
  const root = join(dirname(fileURLToPath(import.meta.url)), '..', 'src')
  const entries = await readdir(root, { recursive: true })
  const files = entries.filter((entry) => entry.endsWith('.js'))
  assert.ok(files.length > 0)
  for (const file of files) {
    const text = await readFile(join(root, file), 'utf8')
    assert.ok(!text.includes('node:child_process'), `${file} must not import child_process`)
    assert.ok(!/\bexecSync\s*\(/.test(text), `${file} must not call execSync`)
    assert.ok(!/\bspawnSync\s*\(/.test(text), `${file} must not call spawnSync`)
  }
})
