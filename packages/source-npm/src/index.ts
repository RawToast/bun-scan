/**
 * npm Registry vulnerability source
 * Queries npm's bulk advisory endpoint for package vulnerabilities
 */

import type { VulnerabilitySource, IgnoreConfig, NpmConfig } from "@repo/core"
import { logger } from "@repo/core"
import { createNpmAuditClient } from "./client.js"
import { createAdvisoryProcessor } from "./processor.js"

// Re-export schemas and types for consumers
export { NpmAuditRequestSchema, NpmAdvisorySchema, NpmAuditResponseSchema } from "./schema.js"

export type { NpmAuditRequest, NpmAdvisory, NpmAuditResponse } from "./schema.js"

// Re-export types
export type { FatalSeverity, NpmSeverity } from "./types.js"

// Re-export processor and client types
export type { NpmAuditClient, CreateNpmAuditClientOptions } from "./client.js"
export type { AdvisoryProcessor } from "./processor.js"

// Re-export factory functions for advanced usage
export { createNpmAuditClient } from "./client.js"
export { createAdvisoryProcessor } from "./processor.js"
export { mapSeverityToLevel, severityToPriority, isCvssScoreFatal } from "./severity.js"

// Re-export constants
export { NPM_AUDIT_API, HTTP, SECURITY } from "./constants.js"

/** Options for creating npm source */
export interface CreateNpmSourceOptions {
  ignore?: IgnoreConfig
  npm?: NpmConfig
  /** When true, throw on internal errors (batch/query failures) instead of continuing with partial results */
  failOnScannerError?: boolean
}

/**
 * Detect if options is new format (CreateNpmSourceOptions) or legacy (IgnoreConfig)
 * New format has `ignore` as an object with ignore/packages, or `npm` key, or `failOnScannerError`
 * Legacy format has `ignore` as an array or `packages` as a record directly
 */
function isNewOptionsFormat(
  options: CreateNpmSourceOptions | IgnoreConfig,
): options is CreateNpmSourceOptions {
  // If it has 'npm' key, it's definitely new format
  if ("npm" in options) return true
  // If 'failOnScannerError' key is present, it's new format
  if ("failOnScannerError" in options) return true
  // If 'ignore' exists and is an object (not array), it's new format
  if (
    "ignore" in options &&
    options.ignore &&
    typeof options.ignore === "object" &&
    !Array.isArray(options.ignore)
  ) {
    return true
  }
  // Otherwise it's legacy format (ignore is array or packages is record)
  return false
}

/**
 * Create an npm Registry vulnerability source
 * Queries npm's bulk advisory endpoint for package vulnerabilities
 */
export function createNpmSource(
  options: CreateNpmSourceOptions | IgnoreConfig = {},
): VulnerabilitySource {
  // Handle legacy signature (just IgnoreConfig) vs new format
  let ignoreConfig: IgnoreConfig
  let npmConfig: NpmConfig | undefined
  let failOnScannerError: boolean | undefined

  if (isNewOptionsFormat(options)) {
    // New format: preserve both new fields and any legacy ignore/packages from the input
    // Note: options may contain both new format fields (failOnScannerError, npm) and
    // legacy fields (ignore array or packages record) - we need to preserve both
    //
    // Handle mixed legacy/new format cases:
    // - { ignore: [...], failOnScannerError: true } - legacy ignore array with new-format flag
    // - { packages: {...}, failOnScannerError: true } - legacy packages config with new-format flag
    // - { ignore: {...}, failOnScannerError: true } - proper new format (pass through)
    const ignoreFromOptions = options.ignore
    const packagesFromOptions = (options as IgnoreConfig).packages

    // Determine ignore config - handle both object and array forms
    if (ignoreFromOptions !== undefined) {
      // If ignore is an array (legacy format), wrap it in an object
      if (Array.isArray(ignoreFromOptions)) {
        ignoreConfig = { ignore: ignoreFromOptions, packages: packagesFromOptions }
      } else {
        // If ignore is an object (new format), use it directly and merge packages if present
        ignoreConfig = {
          ignore: ignoreFromOptions.ignore,
          packages: ignoreFromOptions.packages ?? packagesFromOptions,
        }
      }
    } else if (packagesFromOptions !== undefined) {
      // Only packages provided (legacy format with new-format flag)
      ignoreConfig = { ignore: undefined, packages: packagesFromOptions }
    } else {
      ignoreConfig = {}
    }

    npmConfig = options.npm
    failOnScannerError = options.failOnScannerError
  } else {
    ignoreConfig = options
    npmConfig = undefined
    failOnScannerError = undefined
  }

  const client = createNpmAuditClient({ npm: npmConfig, failOnScannerError })
  const processor = createAdvisoryProcessor(ignoreConfig)

  return {
    name: "npm",

    async scan(packages: Bun.Security.Package[]): Promise<Bun.Security.Advisory[]> {
      if (packages.length === 0) return []

      logger.debug(`[npm] Starting scan for ${packages.length} packages`)

      const advisories = await client.queryVulnerabilities(packages)
      const bunAdvisories = processor.processAdvisories(advisories, packages)

      logger.debug(`[npm] Scan complete: ${bunAdvisories.length} advisories found`)
      return bunAdvisories
    },
  }
}
