import {
  describe,
  it,
  expect,
  beforeAll,
  afterAll,
  beforeEach,
  afterEach,
} from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { getDefaultWritePaths } from '../../src/sandbox/sandbox-utils.js'
import { cleanupBwrapMountPoints } from '../../src/sandbox/linux-sandbox-utils.js'
import { isSupportedPlatform } from '../helpers/platform.js'

/**
 * filesystem.mandatoryDenies and filesystem.defaultWritePaths.
 *
 * mandatoryDenies: false leaves the built-in write denies out, so denyWrite
 * is the whole deny list. defaultWritePaths: false narrows the default write
 * paths to the standard devices and leaves TMPDIR as inherited.
 */

const DEVICES = [
  '/dev/stdout',
  '/dev/stderr',
  '/dev/null',
  '/dev/tty',
  '/dev/dtracehelper',
  '/dev/autofs_nowait',
]

describe('getDefaultWritePaths with defaultWritePaths: false', () => {
  it('returns the standard devices alone', () => {
    expect(
      getDefaultWritePaths(undefined, { defaultWritePaths: false }),
    ).toEqual(DEVICES)
  })

  it('keeps the full list by default', () => {
    const paths = getDefaultWritePaths()
    expect(paths).toContain('/tmp/claude')
    expect(paths).toContain(join(homedir(), '.npm/_logs'))
  })
})

describe('getFsWriteConfig carries the opt-outs', () => {
  const base: SandboxRuntimeConfig = {
    network: { allowedDomains: [], deniedDomains: [] },
    filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
  }

  afterAll(async () => {
    await SandboxManager.reset()
  })

  it('has neither field for the default policy', async () => {
    await SandboxManager.reset()
    await SandboxManager.initialize(base)
    const write = SandboxManager.getFsWriteConfig()
    expect(write.mandatoryDenies).toBeUndefined()
    expect(write.inheritTmpdir).toBeUndefined()
    expect(write.allowOnly).toContain('/tmp/claude')
  })

  it('marks both when both settings are off', async () => {
    await SandboxManager.reset()
    await SandboxManager.initialize({
      ...base,
      filesystem: {
        ...base.filesystem,
        mandatoryDenies: false,
        defaultWritePaths: false,
      },
    })
    const write = SandboxManager.getFsWriteConfig()
    expect(write.mandatoryDenies).toBe(false)
    expect(write.inheritTmpdir).toBe(true)
    expect(write.allowOnly).toEqual(DEVICES)
  })
})

describe.if(isSupportedPlatform)('policy opt-outs in a sandbox', () => {
  const TEST_DIR = realpathSync(tmpdir()) + `/srt-opt-outs-${Date.now()}`
  let originalCwd: string

  const config = (filesystem: {
    mandatoryDenies?: boolean
    defaultWritePaths?: boolean
  }): SandboxRuntimeConfig => ({
    network: { allowedDomains: [], deniedDomains: [] },
    filesystem: {
      denyRead: [],
      allowWrite: [TEST_DIR],
      denyWrite: [],
      ...filesystem,
    },
  })

  function run(
    command: string,
    env: NodeJS.ProcessEnv = process.env,
  ): Promise<{ status: number | null; stdout: string }> {
    return SandboxManager.wrapWithSandbox(command).then(wrapped => {
      const result = spawnSync(wrapped, {
        shell: true,
        encoding: 'utf8',
        timeout: 20000,
        env,
      })
      return { status: result.status, stdout: result.stdout }
    })
  }

  beforeAll(() => {
    originalCwd = process.cwd()
    mkdirSync(join(TEST_DIR, '.git', 'hooks'), { recursive: true })
    mkdirSync(join(TEST_DIR, '.vscode'), { recursive: true })
  })

  afterAll(async () => {
    process.chdir(originalCwd)
    await SandboxManager.reset()
    rmSync(TEST_DIR, { recursive: true, force: true })
  })

  beforeEach(() => {
    // The built-in denies are anchored at the working directory.
    process.chdir(TEST_DIR)
    for (const file of ['.bashrc', '.git/hooks/pre-commit', '.vscode/a.json']) {
      writeFileSync(join(TEST_DIR, file), 'ORIGINAL')
    }
  })

  afterEach(async () => {
    await SandboxManager.reset()
    cleanupBwrapMountPoints({ force: true })
  })

  const PROTECTED = ['.bashrc', '.git/hooks/pre-commit', '.vscode/a.json']

  it('applies the built-in denies by default (control)', async () => {
    await SandboxManager.initialize(config({}))
    for (const file of PROTECTED) {
      await run(`echo MODIFIED > '${file}'`)
      expect(readFileSync(join(TEST_DIR, file), 'utf8')).toBe('ORIGINAL')
    }
  })

  it('leaves the built-in denies out with mandatoryDenies: false', async () => {
    await SandboxManager.initialize(config({ mandatoryDenies: false }))
    for (const file of PROTECTED) {
      const result = await run(`echo MODIFIED > '${file}'`)
      expect(result.status).toBe(0)
      expect(readFileSync(join(TEST_DIR, file), 'utf8').trim()).toBe('MODIFIED')
    }
  })

  it('keeps denyWrite with mandatoryDenies: false', async () => {
    await SandboxManager.initialize({
      ...config({ mandatoryDenies: false }),
      filesystem: {
        ...config({ mandatoryDenies: false }).filesystem,
        denyWrite: [join(TEST_DIR, '.git/hooks')],
      },
    })
    await run(`echo MODIFIED > .git/hooks/pre-commit`)
    expect(readFileSync(join(TEST_DIR, '.git/hooks/pre-commit'), 'utf8')).toBe(
      'ORIGINAL',
    )
  })

  it('points TMPDIR at the sandbox temp directory by default (control)', async () => {
    await SandboxManager.initialize(config({}))
    const marker = join(TEST_DIR, 'host-tmpdir')
    const result = await run('printf %s "$TMPDIR"', {
      ...process.env,
      TMPDIR: marker,
    })
    expect(result.status).toBe(0)
    expect(result.stdout).not.toBe(marker)
  })

  it('keeps TMPDIR and denies /tmp/claude with defaultWritePaths: false', async () => {
    await SandboxManager.initialize(config({ defaultWritePaths: false }))
    const marker = join(TEST_DIR, 'host-tmpdir')
    const tmpdirResult = await run('printf %s "$TMPDIR"', {
      ...process.env,
      TMPDIR: marker,
    })
    expect(tmpdirResult.status).toBe(0)
    expect(tmpdirResult.stdout).toBe(marker)

    mkdirSync('/tmp/claude', { recursive: true })
    const probe = `/tmp/claude/srt-opt-outs-${process.pid}-${Date.now()}`
    const write = await run(`echo x > '${probe}'`)
    expect(write.status).not.toBe(0)
    expect(existsSync(probe)).toBe(false)

    const devNull = await run('echo x > /dev/null')
    expect(devNull.status).toBe(0)
  })

  it('takes the opt-outs from a per-call filesystem override', async () => {
    await SandboxManager.initialize(config({}))
    const wrapped = await SandboxManager.wrapWithSandbox(
      `echo MODIFIED > .bashrc`,
      undefined,
      { filesystem: config({ mandatoryDenies: false }).filesystem },
    )
    const result = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 20000,
    })
    expect(result.status).toBe(0)
    expect(readFileSync(join(TEST_DIR, '.bashrc'), 'utf8').trim()).toBe(
      'MODIFIED',
    )
  })
})
