/**
 * `fullTreeCleanup` / `cleanWorkspaceTree` tests: the on-demand pass a plugin
 * or command runs, never the exit path. Real FFI on scratch trees; the ACLs
 * and labels are observed through icacls, the operator's own tool. Win32-only,
 * like the other real-FFI suites.
 */

import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'

import { grantWrite } from '../src/acl.ts'
import { allocPtrSlot, decodePtr, isNullPtr, win32 } from '../src/ffi.ts'
import type { NativePtr, Win32Bindings } from '../src/ffi.ts'
import { cleanWorkspaceTree, fullTreeCleanup } from '../src/index.ts'
import { makeWellKnownSid } from '../src/token.ts'
import * as abi from '../src/win32-abi.ts'

const isWin32 = process.platform === 'win32'

/** The directory ACL as icacls renders it (the operator-visible form). */
function icaclsText(path: string): string {
  const result = spawnSync('icacls', [path], { encoding: 'utf8' })
  expect(result.status, `icacls failed: ${result.stderr}`).toBe(0)
  return result.stdout
}

/** Convert one SID string to a LocalAlloc'd SID pointer (caller frees). */
function sidFromString(api: Win32Bindings, sid: string): NativePtr {
  const slot = allocPtrSlot()
  if (api.convertStringSidToSidW(sid, slot) === 0) throw new Error(`ConvertStringSidToSidW failed for ${sid}`)
  const ptr = decodePtr(slot)
  if (ptr === null) throw new Error(`ConvertStringSidToSidW returned null for ${sid}`)
  return ptr
}

describe.skipIf(!isWin32)('fullTreeCleanup', () => {
  const scratchDirs: string[] = []
  afterEach(() => {
    for (const dir of scratchDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
  })

  function scratch(): string {
    const dir = mkdtempSync(join(tmpdir(), 'dsh-acl-tree-'))
    scratchDirs.push(dir)
    return dir
  }

  /** A rooted tree with nested directories and one nested file. */
  function grantedTree(): { root: string; nested: string; file: string } {
    const root = scratch()
    const nested = join(root, 'nested', 'deep')
    mkdirSync(nested, { recursive: true })
    const file = join(nested, 'file.txt')
    writeFileSync(file, 'x')
    return { root, nested, file }
  }

  it('clears the capability ACEs and Low labels of a whole granted tree, then reports nothing on a repeat pass', async () => {
    const api = await win32()
    const sid = 'S-1-4-9100-1'
    const { root, nested, file } = grantedTree()
    const capability = sidFromString(api, sid)
    const low = makeWellKnownSid(api, abi.WinLowLabelSid)
    const world = makeWellKnownSid(api, abi.WinWorldSid)
    try {
      grantWrite(api, root, capability, low, world)
      expect(icaclsText(root)).toContain(sid)
      expect(icaclsText(file)).toContain('Mandatory Label')

      const first = fullTreeCleanup(api, root, capability)
      expect(first.failures).toEqual([])
      expect(first.visited).toBeGreaterThanOrEqual(4)
      expect(first.cleaned).toContain(root)
      expect(icaclsText(root)).not.toContain(sid)
      expect(icaclsText(root)).not.toContain('Mandatory Label')
      expect(icaclsText(nested)).not.toContain('Mandatory Label')
      expect(icaclsText(file)).not.toContain('Mandatory Label')

      // Idempotent: a second pass visits the same objects and changes nothing.
      const second = fullTreeCleanup(api, root, capability)
      expect(second.visited).toBe(first.visited)
      expect(second.cleaned).toEqual([])
      expect(second.failures).toEqual([])
    } finally {
      if (!isNullPtr(capability)) api.localFree(capability)
      if (!isNullPtr(low)) api.localFree(low)
      if (!isNullPtr(world)) api.localFree(world)
    }
  })

  it('cleanWorkspaceTree derives the SID from the workspace and reports a missing root instead of throwing', async () => {
    const api = await win32()
    const root = scratch()
    const capability = sidFromString(api, 'S-1-4-9100-2')
    const low = makeWellKnownSid(api, abi.WinLowLabelSid)
    const world = makeWellKnownSid(api, abi.WinWorldSid)
    try {
      grantWrite(api, root, capability, low, world)
    } finally {
      if (!isNullPtr(capability)) api.localFree(capability)
      if (!isNullPtr(low)) api.localFree(low)
      if (!isNullPtr(world)) api.localFree(world)
    }
    // The tree here carries a raw capability SID, not the workspace-derived one,
    // so the derived pass clears the shared label and leaves that foreign ACE.
    const result = cleanWorkspaceTree(root, undefined, api)
    expect(result.failures).toEqual([])
    expect(icaclsText(root)).not.toContain('Mandatory Label')

    const missing = fullTreeCleanup(api, join(root, 'gone'), sidFromString(api, 'S-1-4-9100-3'))
    expect(missing.cleaned).toEqual([])
    expect(missing.failures).toHaveLength(1)
  })
})
