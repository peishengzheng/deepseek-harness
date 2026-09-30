/** Environment variable naming the suffix appended to an artifact's file name. */
export const DESKTOP_ARTIFACT_SUFFIX_ENV: 'DSH_DESKTOP_ARTIFACT_SUFFIX'

/**
 * Read the suffix one packaging run appends to the artifact file name.
 * @param environment - Packaging environment.
 * @returns The validated suffix, or '' when the variable is unset or empty.
 */
export function resolveDesktopArtifactSuffix(environment?: NodeJS.ProcessEnv): string
