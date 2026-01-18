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
}

/**
 * Detect if options is new format (CreateNpmSourceOptions) or legacy (IgnoreConfig)
 * New format has `ignore` as an object with ignore/packages, or `npm` key
 * Legacy format has `ignore` as an array or `packages` as a record directly
 */
function isNewOptionsFormat(
  options: CreateNpmSourceOptions | IgnoreConfig,
): options is CreateNpmSourceOptions {
  // If it has 'npm' key, it's definitely new format
  if ("npm" in options) return true
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

  if (isNewOptionsFormat(options)) {
    ignoreConfig = options.ignore ?? {}
    npmConfig = options.npm
  } else {
    ignoreConfig = options
    npmConfig = undefined
  }

  const client = createNpmAuditClient({ npm: npmConfig })
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
