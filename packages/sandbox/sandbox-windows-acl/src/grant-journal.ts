/**
 * Grant journal: the on-disk record that makes a security-descriptor edit
 * reclaimable after an unclean exit. Each granted directory owns a record
 * (`<GetTempPathW()>\dsh-acl-grants\<sha256(lowercased path)>[:16].grant.json`)
 * and a sibling lease file; the granting process holds the lease under an
 * exclusive byte-range lock for as long as its grant stands, so the lock —
 * released by the kernel when the holder dies — is the liveness proof a later
 * sweep tests before revoking. The record and the lease are separate files
 * because a Windows byte-range lock also blocks reads of the locked bytes.
 * A hard-killed holder therefore leaves a reclaimable record instead of a
 * standing ACE, and a LIVE holder is never revoked out from under it.
 *
 * Ownership rule: a lease answers who revokes. A process that cannot take the
 * lease found a live owner and must not revoke that directory, which is what
 * keeps two sandbox instances sharing one workspace from revoking each other's
 * capability. Leases are re-entrant WITHIN a process (the registry below), so
 * two grants on one directory — a documented shape, since a revoke keeps the
 * shared label while another capability grant remains — keep working; the
 * record then lists every capability SID this process holds there, and a sweep
 * reclaims all of them.
 *
 * Lease files are opened without FILE_SHARE_DELETE (the `acl` module's
 * per-path lock uses the same discipline): a lease deletable under its holder
 * could be recreated and re-locked as a second "owner". Release therefore
 * unlocks, closes, and then deletes — a window in which another process can
 * take the lease, and its record is what a later sweep reclaims.
 * @module @deepseek-ai/dsh-sandbox-windows-acl/grant-journal
 */

import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'

import { revokeWrite } from './acl.ts'
import { allocOverlapped, allocPtrSlot, decodePtr, getTempPath, isInvalidHandle, isNullPtr, throwLastError, throwWin32, win32Sync } from './ffi.ts'
import type { NativePtr, Win32Bindings } from './ffi.ts'
import * as abi from './win32-abi.ts'

/** Journal file suffix separating grant records from unrelated temp files. */
const JOURNAL_SUFFIX = '.grant.json'

/** Lease file suffix: the record's sibling whose exclusive lock proves a live owner. */
const LEASE_SUFFIX = '.lease'

/** Journal directory name under GetTempPathW. */
const JOURNAL_DIRECTORY = 'dsh-acl-grants'

/**
 * One held grant lease. Holding it marks this process as the directory's
 * capability owner: it is the process that revokes the ACEs the grant added,
 * and its death is what makes the record sweepable.
 */
export interface GrantLease {
  /** The granted directory the lease covers. */
  readonly path: string
  /** Drop this holder's capability SID from the record, releasing the lock with the last holder (idempotent). */
  release(): void
}

/** One sweep outcome: what was reclaimed and what could not be. */
export interface GrantSweepResult {
  /** Directories whose stale grant was revoked. */
  readonly revoked: readonly string[]
  /** Per-entry failures; the sweep continues past each one. */
  readonly failures: readonly unknown[]
}

/** One recorded grant: the granted directory and every capability SID its ACEs name. */
interface JournalEntry {
  readonly path: string
  readonly sids: readonly string[]
}

/** One open lease file: the lock handle and its zeroed OVERLAPPED record. */
interface LockedJournal {
  readonly handle: NativePtr
  readonly overlapped: NativePtr
}

/** One journal file this process holds: its lease, its live holders, and the SIDs they own there. */
interface HeldLease extends LockedJournal {
  readonly path: string
  readonly leasePath: string
  /** Capability SID to the number of leases holding it. */
  readonly sids: Map<string, number>
  /** Lease objects sharing this record; the record goes when the last one releases. */
  holders: number
}

/** Process-local lease registry, keyed by journal file path. */
const heldLeases = new Map<string, HeldLease>()

/**
 * The grant-journal directory under GetTempPathW.
 * @param api - the binding table.
 * @returns the absolute directory holding grant records and their leases.
 */
export function grantJournalDirectory(api: Win32Bindings): string {
  return join(getTempPath(api), JOURNAL_DIRECTORY)
}

/**
 * The journal file recording one granted directory. The lowercased path hashes
 * to a fixed 16-hex-character name, so Windows's case-insensitive path
 * spellings map onto one record and the name is derivable from the directory
 * alone (a sweep needs no index).
 * @param api - the binding table.
 * @param path - the granted directory (absolute).
 * @returns the absolute journal file path for that directory.
 */
export function grantJournalPath(api: Win32Bindings, path: string): string {
  return join(grantJournalDirectory(api), `${journalKey(path)}${JOURNAL_SUFFIX}`)
}

/**
 * The lease file whose exclusive lock proves the record's owner is alive. It
 * carries no data: a Windows byte-range lock also blocks reads of the locked
 * bytes, so the record and the lock cannot share one file.
 * @param api - the binding table.
 * @param path - the granted directory (absolute).
 * @returns the absolute lease file path for that directory.
 */
export function grantLeasePath(api: Win32Bindings, path: string): string {
  return join(grantJournalDirectory(api), `${journalKey(path)}${LEASE_SUFFIX}`)
}

/**
 * The 16-hex-character journal key for one directory.
 * @param path - the granted directory (absolute).
 * @returns the hashed key shared by the record and its lease.
 */
function journalKey(path: string): string {
  return createHash('sha256').update(path.toLowerCase()).digest('hex').slice(0, 16)
}

/**
 * The lease path matching one record file name.
 * @param api - the binding table.
 * @param recordName - a `*.grant.json` file name from the journal directory.
 * @returns the absolute lease path for that record.
 */
function leasePathForRecord(api: Win32Bindings, recordName: string): string {
  return join(grantJournalDirectory(api), `${recordName.slice(0, -JOURNAL_SUFFIX.length)}${LEASE_SUFFIX}`)
}

/**
 * Write one record: the directory plus every capability SID its live holders own.
 * @param journalPath - the journal file to write.
 * @param path - the granted directory.
 * @param sids - the capability SIDs with at least one live holder.
 */
function writeJournalEntry(journalPath: string, path: string, sids: Iterable<string>): void {
  writeFileSync(journalPath, JSON.stringify({ path, sids: [...sids] }), 'utf8')
}

/**
 * Open one lease file and take its exclusive lock without waiting.
 * @param api - the binding table.
 * @param leasePath - the lease file to open and lock.
 * @returns the locked handle, or null when another process holds the lease.
 */
function lockLease(api: Win32Bindings, leasePath: string): LockedJournal | null {
  mkdirSync(dirname(leasePath), { recursive: true })
  const handle = api.createFileW(
    leasePath,
    abi.GENERIC_READ | abi.GENERIC_WRITE,
    abi.FILE_SHARE_READ | abi.FILE_SHARE_WRITE,
    null, abi.OPEN_ALWAYS, 0, null,
  )
  if (isInvalidHandle(handle)) throwLastError(api, 'CreateFileW', leasePath)
  const overlapped = allocOverlapped() // stays zeroed: offset 0, hEvent NULL
  if (api.lockFileEx(
    handle, abi.LOCKFILE_EXCLUSIVE_LOCK | abi.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, overlapped,
  ) === 0) {
    const win32Code = api.getLastError()
    api.closeHandle(handle) // best-effort on the lock-failure path
    if (win32Code === abi.ERROR_LOCK_VIOLATION) return null
    throwWin32(api, 'LockFileEx', win32Code, leasePath)
  }
  return { handle, overlapped }
}

/**
 * Unlock and close one lease file. A caller that keeps the record alive on
 * failure leaves the lease to the kernel's process teardown.
 * @param api - the binding table.
 * @param locked - the open lease file.
 * @param leasePath - the lease file path for error details.
 */
function unlockLease(api: Win32Bindings, locked: LockedJournal, leasePath: string): void {
  if (api.unlockFileEx(locked.handle, 0, 1, 0, locked.overlapped) === 0) {
    const win32Code = api.getLastError()
    api.closeHandle(locked.handle) // best-effort on the unlock-failure path
    throwWin32(api, 'UnlockFileEx', win32Code, leasePath)
  }
  if (api.closeHandle(locked.handle) === 0) throwLastError(api, 'CloseHandle', `lease file ${leasePath}`)
}

/**
 * Read one journal record. An unparsable record fails loud: a partial write is
 * the only way to produce one, and the file path is what the operator needs to
 * reclaim it.
 * @param journalPath - the journal file to read.
 * @returns the recorded grant, or undefined for a record a crash left empty.
 */
function readJournalEntry(journalPath: string): JournalEntry | undefined {
  if (!existsSync(journalPath)) return undefined // no grant has been recorded for this directory yet
  const text = readFileSync(journalPath, 'utf8').trim()
  if (text.length === 0) return undefined
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch (error) {
    throw new Error(`grant journal ${journalPath} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`)
  }
  if (typeof parsed !== 'object' || parsed === null) throw new Error(`grant journal ${journalPath} is not a JSON object`)
  const record = parsed as Record<string, unknown>
  const path = record['path']
  const sids = record['sids']
  if (typeof path !== 'string' || path.length === 0 || !Array.isArray(sids) || sids.length === 0
    || !sids.every((sid): sid is string => typeof sid === 'string' && sid.length > 0)) {
    throw new Error(`grant journal ${journalPath} does not record a path and its capability SIDs`)
  }
  return { path, sids }
}

/**
 * Revoke one capability SID's ACEs on one recorded directory, which also clears
 * the shared Low label when no other capability grant remains there.
 * @param api - the binding table.
 * @param path - the recorded directory.
 * @param sid - the recorded capability SID.
 */
function revokeJournalSid(api: Win32Bindings, path: string, sid: string): void {
  const slot = allocPtrSlot()
  if (api.convertStringSidToSidW(sid, slot) === 0) throwLastError(api, 'ConvertStringSidToSidW', sid)
  const sidPtr = decodePtr(slot)
  if (sidPtr === null) throwLastError(api, 'ConvertStringSidToSidW', `null SID for ${sid}`)
  let failure: unknown
  try {
    revokeWrite(api, path, sidPtr)
  } catch (error) {
    failure = error
  }
  const freed = api.localFree(sidPtr)
  if (failure !== undefined) throw failure
  if (!isNullPtr(freed)) throwLastError(api, 'LocalFree', `grant journal SID ${sid}`)
}

/**
 * Take the lease for one granted directory, so this process owns the ACEs the
 * grant adds (or reuses) and revokes them when it stops.
 *
 * A null result means a LIVE process already holds the lease: this caller did
 * not take the directory's capability and must not revoke it. Within one
 * process the lease is re-entrant — a second holder joins the existing record,
 * which then names every capability SID this process holds there. A record
 * found under a lease this process could take belongs to a holder that died,
 * so its ACEs are revoked before the new record is written.
 * @param api - the binding table.
 * @param path - the granted directory (absolute).
 * @param sid - the capability SID this process grants on that directory.
 * @returns the lease, or null when another live process owns the grant.
 */
export function holdGrantLease(api: Win32Bindings, path: string, sid: string): GrantLease | null {
  const journalPath = grantJournalPath(api, path)
  const existing = heldLeases.get(journalPath)
  if (existing !== undefined) {
    existing.holders += 1
    existing.sids.set(sid, (existing.sids.get(sid) ?? 0) + 1)
    writeJournalEntry(journalPath, path, existing.sids.keys())
    return makeLease(api, journalPath, existing, sid)
  }
  const leasePath = grantLeasePath(api, path)
  const locked = lockLease(api, leasePath)
  if (locked === null) return null
  const entry: HeldLease = { ...locked, path, leasePath, sids: new Map([[sid, 1]]), holders: 1 }
  try {
    const previous = readJournalEntry(journalPath)
    if (previous !== undefined) {
      if (previous.path !== path) {
        throw new Error(`grant journal ${journalPath} records ${previous.path}, not ${path}`)
      }
      // The lease was free, so every recorded capability belongs to a dead
      // holder: reclaim them before this process grants the directory.
      for (const staleSid of previous.sids) revokeJournalSid(api, path, staleSid)
    }
    writeJournalEntry(journalPath, path, entry.sids.keys())
  } catch (error) {
    const failures: unknown[] = [error]
    try {
      unlockLease(api, locked, leasePath)
    } catch (unlockError) {
      failures.push(unlockError)
    }
    throw failures.length === 1
      ? error
      : new AggregateError(failures, `grant journal ${journalPath} failed and its lease release also failed`)
  }
  heldLeases.set(journalPath, entry)
  return makeLease(api, journalPath, entry, sid)
}

/**
 * One lease handle over a held record: its release drops this holder's
 * capability SID, rewrites the record while other holders remain, and with the
 * last holder deletes the record and its lease.
 * @param api - the binding table.
 * @param journalPath - the record this lease covers.
 * @param entry - the process-local held entry.
 * @param sid - the capability SID this lease owns.
 * @returns the lease.
 */
function makeLease(api: Win32Bindings, journalPath: string, entry: HeldLease, sid: string): GrantLease {
  let released = false
  return {
    path: entry.path,
    release: () => {
      if (released) return
      released = true
      const count = entry.sids.get(sid) ?? 0
      if (count <= 1) entry.sids.delete(sid)
      else entry.sids.set(sid, count - 1)
      entry.holders -= 1
      if (entry.holders > 0) {
        writeJournalEntry(journalPath, entry.path, entry.sids.keys())
        return
      }
      heldLeases.delete(journalPath)
      unlockLease(api, entry, entry.leasePath)
      rmSync(journalPath, { force: true })
      rmSync(entry.leasePath, { force: true })
    },
  }
}

/**
 * Revoke every grant record whose holder died: acquire each record's lease
 * without waiting (success proves the holder is gone), revoke the recorded
 * ACEs, then drop the record. Records held by live processes are left alone,
 * and a record whose directory no longer exists is dropped without revoking.
 *
 * Failures are collected per record rather than thrown, matching the
 * package's best-effort cleanup contract; a record whose lease cannot be
 * released keeps its lease until this process exits, so a later sweep still
 * reclaims it.
 * @param api - the binding table; the cached one is resolved when omitted.
 * @returns the revoked directories and every per-record failure.
 */
export function sweepStaleGrantLeases(api?: Win32Bindings): GrantSweepResult {
  const bindings = api ?? win32Sync()
  const directory = grantJournalDirectory(bindings)
  const revoked: string[] = []
  const failures: unknown[] = []
  if (!existsSync(directory)) return { revoked, failures }
  for (const name of readdirSync(directory).sort()) {
    if (!name.endsWith(JOURNAL_SUFFIX)) continue
    const journalPath = join(directory, name)
    const leasePath = leasePathForRecord(bindings, name)
    let locked: LockedJournal | null
    try {
      locked = lockLease(bindings, leasePath)
    } catch (error) {
      failures.push(error)
      continue
    }
    if (locked === null) continue // a live holder owns this grant
    let consumed = false
    try {
      const entry = readJournalEntry(journalPath)
      if (entry === undefined) {
        consumed = true // a crash between lock and write recorded nothing
      } else if (!existsSync(entry.path)) {
        consumed = true // the directory is gone; its ACEs went with it
      } else {
        for (const sid of entry.sids) revokeJournalSid(bindings, entry.path, sid)
        revoked.push(entry.path)
        consumed = true
      }
    } catch (error) {
      // An unparsable record keeps its file: the capability SIDs it named are
      // unknown, so deleting it would leak exactly what the journal exists to
      // reclaim. The repeated warning is the operator's signal to remove it.
      failures.push(error)
    }
    try {
      unlockLease(bindings, locked, leasePath)
    } catch (error) {
      failures.push(error)
      continue // keep the record: this process holds the lease until it exits
    }
    if (!consumed) continue
    for (const path of [journalPath, leasePath]) {
      try {
        rmSync(path, { force: true })
      } catch (error) {
        failures.push(error)
      }
    }
  }
  return { revoked, failures }
}
