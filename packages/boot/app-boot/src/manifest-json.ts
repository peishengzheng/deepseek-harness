/** JSON text of package files read from disk: package manifests and their locale resources. */

/**
 * Parse JSON text read from a package file, dropping one leading UTF-8 BOM (U+FEFF).
 * Windows editors and PowerShell 5.1 write the mark into `package.json` files that
 * Node's module loader, npm, and pnpm still accept, so DSH readers accept them too.
 * @param raw - file contents decoded as UTF-8.
 * @returns the parsed value.
 * @throws SyntaxError when the text after the mark is not valid JSON.
 */
export function parseManifestJson(raw: string): unknown {
  return JSON.parse(raw.charCodeAt(0) === 0xFEFF ? raw.slice(1) : raw)
}
