/**
 * Grant-journal tests: the lease that marks the owning process and the sweep
 * that reclaims records an unclean exit left behind. Real FFI and real
 * scratch directories (ACEs are observed through icacls, the operator's own
 * tool); win32-only, like the other real-FFI suites.
 */

import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'

import { grantWrite } from '../src/acl.ts'
import { allocOverlapped, allocPtrSlot, decodePtr, isInvalidHandle, isNullPtr, win32 } from '../src/ffi.ts'
import type { NativePtr, Win32Bindings } from '../src/ffi.ts'
import { grantJournalPath, grantLeasePath, holdGrantLease, sweepStaleGrantLeases } from '../src/grant-journal.ts'
import { makeWellKnownSid } from '../src/token.ts'
import * as abi from '../src/win32-abi.ts'

const isWin32 = process.platform === 'win32'

/** The directory DACL as icacls renders it (the operator-visible form). */
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

/** Apply the capability ACE plus the Low label a real grant writes. */
function applyGrant(api: Win32Bindings, path: string, sid: string): void {
  const capability = sidFromString(api, sid)
  const low = makeWellKnownSid(api, abi.WinLowLabelSid)
  const world = makeWellKnownSid(api, abi.WinWorldSid)
  try {
    grantWrite(api, path, capability, low, world)
  } finally {
    if (!isNullPtr(capability)) api.localFree(capability)
    if (!isNullPtr(low)) api.localFree(low)
    if (!isNullPtr(world)) api.localFree(world)
  }
}

/** Hold the lease file with a raw handle, exactly as a DIFFERENT process would. */
function lockForeign(api: Win32Bindings, leasePath: string): () => void {
  const handle = api.createFileW(
    leasePath,
    abi.GENERIC_READ | abi.GENERIC_WRITE,
    abi.FILE_SHARE_READ | abi.FILE_SHARE_WRITE,
    null, abi.OPEN_ALWAYS, 0, null,
  )
  expect(isInvalidHandle(handle), 'foreign CreateFileW failed').toBe(false)
  const overlapped = allocOverlapped()
  expect(api.lockFileEx(handle, abi.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, overlapped), 'foreign LockFileEx failed').toBe(1)
  return () => {
    api.unlockFileEx(handle, 0, 1, 0, overlapped)
    api.closeHandle(handle)
  }
}

describe.skipIf(!isWin32)('grant journal', () => {
  const scratchDirs: string[] = []
  afterEach(() => {
    for (const dir of scratchDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
  })

  function scratch(): string {
    const dir = mkdtempSync(join(tmpdir(), 'dsh-acl-journal-'))
    scratchDirs.push(dir)
    return dir
  }

  it('a lease records the directory and its capability SID, and release removes the record', async () => {
    const api = await win32()
    const dir = scratch()
    const journalPath = grantJournalPath(api, dir)
    const lease = holdGrantLease(api, dir, 'S-1-4-9001-1')
    expect(lease?.path).toBe(dir)
    expect(JSON.parse(readFileSync(journalPath, 'utf8'))).toEqual({ path: dir, sids: ['S-1-4-9001-1'] })
    lease?.release()
    expect(existsSync(journalPath)).toBe(false)
    // Idempotent: a second release is a no-op rather than a failure.
    lease?.release()
  })

  it('leases are re-entrant per process: the record names every held SID and the last release clears it', async () => {
    const api = await win32()
    const dir = scratch()
    const journalPath = grantJournalPath(api, dir)
    const first = holdGrantLease(api, dir, 'S-1-4-9001-2')
    const second = holdGrantLease(api, dir, 'S-1-4-9001-3')
    expect(JSON.parse(readFileSync(journalPath, 'utf8'))).toEqual({ path: dir, sids: ['S-1-4-9001-2', 'S-1-4-9001-3'] })
    first?.release()
    expect(JSON.parse(readFileSync(journalPath, 'utf8'))).toEqual({ path: dir, sids: ['S-1-4-9001-3'] })
    second?.release()
    expect(existsSync(journalPath)).toBe(false)
  })

  it('a lease another file object holds is not takeable, and the sweep leaves that grant alone', async () => {
    const api = await win32()
    const dir = scratch()
    const journalPath = grantJournalPath(api, dir)
    applyGrant(api, dir, 'S-1-4-9001-4')
    writeFileSync(journalPath, JSON.stringify({ path: dir, sids: ['S-1-4-9001-4'] }), 'utf8')
    const release = lockForeign(api, grantLeasePath(api, dir))
    try {
      expect(holdGrantLease(api, dir, 'S-1-4-9001-5')).toBeNull()
      // The shared journal directory may hold records from other runs; only
      // this directory's outcome is this spec's to assert.
      expect(sweepStaleGrantLeases(api).revoked).not.toContain(dir)
      expect(icaclsText(dir)).toContain('S-1-4-9001-4')
      expect(existsSync(journalPath)).toBe(true)
    } finally {
      release()
    }
  })

  it('taking over a dead holder\'s record revokes the ACEs it named before recording the new SID', async () => {
    const api = await win32()
    const dir = scratch()
    const journalPath = grantJournalPath(api, dir)
    applyGrant(api, dir, 'S-1-4-9001-6')
    writeFileSync(journalPath, JSON.stringify({ path: dir, sids: ['S-1-4-9001-6'] }), 'utf8')
    const lease = holdGrantLease(api, dir, 'S-1-4-9001-7')
    try {
      expect(lease).not.toBeNull()
      expect(icaclsText(dir)).not.toContain('S-1-4-9001-6')
      expect(JSON.parse(readFileSync(journalPath, 'utf8'))).toEqual({ path: dir, sids: ['S-1-4-9001-7'] })
    } finally {
      lease?.release()
    }
  })

  it('the sweep revokes a dead holder\'s ACEs and label, and drops a record whose directory is gone', async () => {
    const api = await win32()
    const stale = scratch()
    const missing = join(scratch(), 'gone')
    applyGrant(api, stale, 'S-1-4-9001-8')
    expect(icaclsText(stale)).toContain('S-1-4-9001-8')
    writeFileSync(grantJournalPath(api, stale), JSON.stringify({ path: stale, sids: ['S-1-4-9001-8'] }), 'utf8')
    writeFileSync(grantJournalPath(api, missing), JSON.stringify({ path: missing, sids: ['S-1-4-9001-9'] }), 'utf8')
    const sweep = sweepStaleGrantLeases(api)
    expect(sweep.revoked).toContain(stale)
    expect(icaclsText(stale)).not.toContain('S-1-4-9001-8')
    expect(icaclsText(stale)).not.toContain('Mandatory Label')
    expect(existsSync(grantJournalPath(api, stale))).toBe(false)
    expect(existsSync(grantLeasePath(api, stale))).toBe(false)
    expect(existsSync(grantJournalPath(api, missing))).toBe(false)
  })

  it('an unparsable record is reported as a failure and kept for the operator', async () => {
    const api = await win32()
    const dir = scratch()
    const journalPath = grantJournalPath(api, dir)
    writeFileSync(journalPath, '{"path":', 'utf8')
    const sweep = sweepStaleGrantLeases(api)
    expect(sweep.revoked).not.toContain(dir)
    expect(sweep.failures.map(String).join('\n')).toContain('is not valid JSON')
    expect(existsSync(journalPath)).toBe(true)
  })
})
