/**
 * Server-side write-grant materialization. One instance covers one capability
 * SID: `add` records a directory whose ACEs and Low label the instance then
 * owns, and `dispose` revokes the paths it owns — which clears the shared
 * label once no other capability grant remains on the directory.
 *
 * Ownership is per directory and per process. A revocable `add` takes the
 * directory's lease first ({@link holdGrantLease}); a caller that cannot take
 * it found a live owner and never revokes that directory, so two sandbox
 * instances sharing one workspace cannot revoke each other's capability. A
 * standing path is the caller's declared reuse cache: it is never revoked.
 *
 * Fail-closed: `add` throws on any grant failure and the caller disposes the
 * instance (revoking every path granted so far); `dispose` reports every
 * cleanup failure. The lease of a path whose revoke failed is deliberately
 * kept, so the journal sweep reclaims it after this process exits.
 * @module @deepseek-ai/dsh-sandbox-windows-acl/grant
 */

import { grantWrite, revokeWrite } from './acl.ts'
import { allocPtrSlot, decodePtr, isNullPtr, throwLastError, win32Sync } from './ffi.ts'
import type { NativePtr, Win32Bindings } from './ffi.ts'
import { holdGrantLease } from './grant-journal.ts'
import type { GrantLease } from './grant-journal.ts'
import { makeWellKnownSid } from './token.ts'
import * as abi from './win32-abi.ts'

/** One revocable grant: the directory plus the lease marking this process its owner. */
interface RevocableGrant {
  readonly path: string
  readonly lease: GrantLease
}

/**
 * One write SID's grant materialization: the parsed SID pointer plus every
 * directory whose DACL currently carries its ACE and whose label ACL carries
 * the Low mandatory label. Revocable paths are owned by this instance: its
 * lease on each directory is what authorizes the revoke at dispose, and a
 * directory another live process already owns is recorded as foreign and left
 * untouched. Standing paths are the caller's reuse cache and outlive the
 * instance. Create with {@link AclWriteGrant.create}; dispose revokes the
 * revocable paths and frees every SID.
 */
export class AclWriteGrant {
  /** The write SID in SDDL string form. */
  readonly writeSid: string
  private readonly api: Win32Bindings
  private readonly sidPtr: NativePtr
  private readonly lowLabelSidPtr: NativePtr
  private readonly worldSidPtr: NativePtr
  private readonly revocable: RevocableGrant[] = []
  private readonly standingPaths: string[] = []
  private readonly foreignPaths: string[] = []

  private constructor(
    api: Win32Bindings,
    sidPtr: NativePtr,
    lowLabelSidPtr: NativePtr,
    worldSidPtr: NativePtr,
    writeSid: string,
  ) {
    this.api = api
    this.sidPtr = sidPtr
    this.lowLabelSidPtr = lowLabelSidPtr
    this.worldSidPtr = worldSidPtr
    this.writeSid = writeSid
  }

  /**
   * Parse the SID string, create the Low integrity SID the grants label with
   * and the world SID their ambient-delete deny names, and open the binding
   * table (lazily, once per server). Fail-closed: any failure throws — nothing
   * is granted yet.
   * @param writeSid - the workspace (`S-1-4-x-y`) or temp (`S-1-4-x-y-1`) capability SID string.
   * @param api - optional already-resolved bindings (tests).
   * @returns the ready grant (no ACEs yet).
   */
  static create(writeSid: string, api?: Win32Bindings): AclWriteGrant {
    const bindings = api ?? win32Sync()
    const sidSlot = allocPtrSlot()
    if (bindings.convertStringSidToSidW(writeSid, sidSlot) === 0) {
      throwLastError(bindings, 'ConvertStringSidToSidW', writeSid)
    }
    const sidPtr = decodePtr(sidSlot)
    if (sidPtr === null) throwLastError(bindings, 'ConvertStringSidToSidW', `null SID for ${writeSid}`)
    try {
      const lowLabelSidPtr = makeWellKnownSid(bindings, abi.WinLowLabelSid)
      try {
        const worldSidPtr = makeWellKnownSid(bindings, abi.WinWorldSid)
        return new AclWriteGrant(bindings, sidPtr, lowLabelSidPtr, worldSidPtr, writeSid)
      } catch (error) {
        // The Low label SID is LocalAlloc'd: release it before the world-SID
        // failure propagates to the sidPtr release below.
        bindings.localFree(lowLabelSidPtr)
        throw error
      }
    } catch (error) {
      bindings.localFree(sidPtr)
      throw error
    }
  }

  /**
   * Grant the write ACE, the ambient-delete deny, and the Low mandatory label
   * on one directory (idempotent: an already-standing exact ACE, deny, and
   * label skip the eager full-tree re-propagation — see {@link grantWrite}).
   *
   * A revocable add takes the directory's lease BEFORE the grant: a post-apply
   * throw (a LocalFree failure after SetNamedSecurityInfoW succeeded) must
   * still revoke it, and revoking an ungranted path is a no-op merge. A
   * directory whose lease another live process holds is recorded as foreign
   * and never revoked by this instance; re-adding a directory this instance
   * already owns reuses its lease instead of opening a second one.
   * @param path - the directory whose DACL and label gain the grant.
   * @param standing - the edits outlive this instance (the caller's reuse
   *   cache; dispose() skips revoking it). Default false (revoked on dispose).
   */
  add(path: string, standing = false): void {
    if (standing) {
      this.standingPaths.push(path)
      grantWrite(this.api, path, this.sidPtr, this.lowLabelSidPtr, this.worldSidPtr)
      return
    }
    const owned = this.revocable.find(entry => entry.path === path)
    const lease = owned?.lease ?? holdGrantLease(this.api, path, this.writeSid)
    if (lease === null) {
      if (!this.foreignPaths.includes(path)) this.foreignPaths.push(path)
    } else if (owned === undefined) {
      this.revocable.push({ path, lease })
    }
    grantWrite(this.api, path, this.sidPtr, this.lowLabelSidPtr, this.worldSidPtr)
  }

  /** Every directory currently carrying the grant, in grant order (standing, owned revocable, then foreign). */
  get paths(): readonly string[] {
    return [...this.standingPaths, ...this.revocable.map(entry => entry.path), ...this.foreignPaths]
  }

  /**
   * Revoke every owned revocable grant (standing and foreign security
   * descriptor edits stay) and free the SIDs; reports every cleanup failure.
   * A lease survives a failed revoke, so the journal sweep reclaims that
   * directory after this process exits.
   */
  dispose(): void {
    const failures: unknown[] = []
    for (const entry of this.revocable) {
      try {
        revokeWrite(this.api, entry.path, this.sidPtr)
        entry.lease.release()
      } catch (error) {
        failures.push(error)
      }
    }
    for (const [label, sidPtr] of [
      ['write SID', this.sidPtr],
      ['Low label SID', this.lowLabelSidPtr],
      ['world SID', this.worldSidPtr],
    ] as const) {
      try {
        const freed = this.api.localFree(sidPtr)
        if (!isNullPtr(freed)) throwLastError(this.api, 'LocalFree', label)
      } catch (error) {
        failures.push(error)
      }
    }
    if (failures.length > 0) {
      throw new AggregateError(failures, `AclWriteGrant dispose completed with ${failures.length} cleanup failure(s)`)
    }
  }
}
