import type { VulnerabilitySource, IgnoreConfig, OsvConfig } from "@repo/core"
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
}

/**
 * Detect if options is new format (CreateOSVSourceOptions) or legacy (IgnoreConfig)
 * New format has `ignore` as an object with ignore/packages, or `osv` key
 * Legacy format has `ignore` as an array or `packages` as a record directly
 */
function isNewOptionsFormat(
  options: CreateOSVSourceOptions | IgnoreConfig,
): options is CreateOSVSourceOptions {
  // If it has 'osv' key, it's definitely new format
  if ("osv" in options) return true
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

  if (isNewOptionsFormat(options)) {
    ignoreConfig = options.ignore ?? {}
    osvConfig = options.osv
  } else {
    ignoreConfig = options
    osvConfig = undefined
  }

  const client = createOSVClient({ osv: osvConfig })
  const processor = createVulnerabilityProcessor(ignoreConfig)

  return {
    name: "osv",

    async scan(packages: Bun.Security.Package[]): Promise<Bun.Security.Advisory[]> {
      logger.info(`[OSV] Starting scan for ${packages.length} packages`)

      const vulnerabilities = await client.queryVulnerabilities(packages)
      const advisories = processor.processVulnerabilities(vulnerabilities, packages)

      logger.info(`[OSV] Scan complete: ${advisories.length} advisories found`)
      return advisories
    },
  }
}
