import type { VulnerabilitySource, IgnoreConfig, OsvConfig, IgnorePackageRule } from "@repo/core"
import { logger } from "@repo/core"
import { createOSVClient } from "./client.js"
import { createVulnerabilityProcessor } from "./processor.js"

// Re-export schemas and types for consumers
export {
  OSVQuerySchema,
  OSVAffectedSchema,
  OSVVulnerabilitySchema,
  OSVResponseSchema,
  OSVBatchQuerySchema,
  OSVBatchResponseSchema,
} from "./schema.js"

export type {
  OSVQuery,
  OSVAffected,
  OSVVulnerability,
  OSVResponse,
  OSVBatchQuery,
  OSVBatchResponse,
  OSVSeverity,
} from "./schema.js"

// Re-export processor and client types
export type { OSVClient, CreateOSVClientOptions } from "./client.js"
export type { VulnerabilityProcessor } from "./processor.js"

// Re-export factory functions for advanced usage
export { createOSVClient } from "./client.js"
export { createVulnerabilityProcessor } from "./processor.js"
export { mapSeverityToLevel } from "./severity.js"
export { isPackageAffected } from "./semver.js"

/** Options for creating OSV source */
export interface CreateOSVSourceOptions {
  ignore?: IgnoreConfig
  osv?: OsvConfig
  /** When true, throw on internal errors (batch/query failures) instead of continuing with partial results */
  failOnScannerError?: boolean
}

/**
 * Detect if options is new format (CreateOSVSourceOptions) or legacy (IgnoreConfig)
 * New format has `ignore` as an object with ignore/packages, or `osv` key, or `failOnScannerError`
 * Legacy format has `ignore` as an array or `packages` as a record directly
 */
function isNewOptionsFormat(
  options: CreateOSVSourceOptions | IgnoreConfig,
): options is CreateOSVSourceOptions {
  // If it has 'osv' key, it's definitely new format
  if ("osv" in options) return true
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
 * Create an OSV.dev vulnerability source
 * Queries Google's OSV database for npm package vulnerabilities
 */
export function createOSVSource(
  options: CreateOSVSourceOptions | IgnoreConfig = {},
): VulnerabilitySource {
  // Handle legacy signature (just IgnoreConfig) vs new format
  let ignoreConfig: IgnoreConfig
  let osvConfig: OsvConfig | undefined
  let failOnScannerError: boolean | undefined

  if (isNewOptionsFormat(options)) {
    // New format: preserve both new fields and any legacy ignore/packages from the input
    // Note: options may contain both new format fields (failOnScannerError, osv) and
    // legacy fields (ignore array or packages record) - we need to preserve both
    //
    // Handle mixed legacy/new format cases:
    // - { ignore: [...], failOnScannerError: true } - legacy ignore array with new-format flag
    // - { packages: {...}, failOnScannerError: true } - legacy packages config with new-format flag
    // - { ignore: {...}, failOnScannerError: true } - proper new format (pass through)
    const ignoreFromOptions = options.ignore
    const packagesFromOptions: Record<string, IgnorePackageRule> | undefined =
      "packages" in options
        ? (options.packages as Record<string, IgnorePackageRule> | undefined)
        : undefined

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

    osvConfig = options.osv
    failOnScannerError = options.failOnScannerError
  } else {
    ignoreConfig = options
    osvConfig = undefined
    failOnScannerError = undefined
  }

  const client = createOSVClient({ osv: osvConfig, failOnScannerError })
  const processor = createVulnerabilityProcessor(ignoreConfig)

  return {
    name: "osv",

    async scan(packages: Bun.Security.Package[]): Promise<Bun.Security.Advisory[]> {
      logger.debug(`[OSV] Starting scan for ${packages.length} packages`)

      const vulnerabilities = await client.queryVulnerabilities(packages)
      const advisories = processor.processVulnerabilities(vulnerabilities, packages)

      logger.debug(`[OSV] Scan complete: ${advisories.length} advisories found`)
      return advisories
    },
  }
}
