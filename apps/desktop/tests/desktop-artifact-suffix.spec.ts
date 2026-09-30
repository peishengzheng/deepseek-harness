import { describe, expect, it } from 'vitest'
import { DESKTOP_ARTIFACT_SUFFIX_ENV, resolveDesktopArtifactSuffix } from '../scripts/desktop-artifact-suffix.mjs'

describe('desktop artifact suffix', () => {
  it('reads no suffix from an unset or empty variable', () => {
    expect(resolveDesktopArtifactSuffix({})).toBe('')
    expect(resolveDesktopArtifactSuffix({ [DESKTOP_ARTIFACT_SUFFIX_ENV]: '' })).toBe('')
  })

  it('keeps a dash-separated lowercase fragment', () => {
    expect(resolveDesktopArtifactSuffix({ [DESKTOP_ARTIFACT_SUFFIX_ENV]: '-no-low-level' })).toBe('-no-low-level')
  })

  it.each([
    'no-low-level',
    '-',
    '-No-Low-Level',
    '-no_low_level',
    '-no low level',
    '--no',
    '-no-',
    '-no/../level',
    '-no.exe',
  ])('rejects %j, which could not stay a file-name fragment', (value) => {
    expect(() => resolveDesktopArtifactSuffix({ [DESKTOP_ARTIFACT_SUFFIX_ENV]: value }))
      .toThrow(`${DESKTOP_ARTIFACT_SUFFIX_ENV} must be dash-separated lowercase alphanumerics`)
  })
})
