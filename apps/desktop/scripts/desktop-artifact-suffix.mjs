/** The operator-selected artifact-name suffix for a local build variant. */

/** Environment variable naming the suffix appended to an artifact's file name. */
export const DESKTOP_ARTIFACT_SUFFIX_ENV = 'DSH_DESKTOP_ARTIFACT_SUFFIX'

/**
 * Read the suffix one packaging run appends to the artifact file name, after
 * the unsigned marker. It distinguishes a locally built variant — a different
 * embedded composition, such as a sandbox backend without the Windows
 * restricted-token runner — from the build its version and target alone would
 * name, so two such installers cannot be confused on disk or in a handover.
 * The value is a file-name fragment, not a release identifier: release
 * packaging and upload own the release naming and reject anything else.
 * @param {NodeJS.ProcessEnv} environment - Packaging environment.
 * @returns {string} The validated suffix, or '' when the variable is unset or empty.
 */
export function resolveDesktopArtifactSuffix(environment = process.env) {
  const value = environment[DESKTOP_ARTIFACT_SUFFIX_ENV]
  if (value === undefined || value === '') return ''
  if (!/^-[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(value)) {
    throw new Error(`desktop package: ${DESKTOP_ARTIFACT_SUFFIX_ENV} must be dash-separated lowercase alphanumerics starting with '-', got ${JSON.stringify(value)}`)
  }
  return value
}
