/**
 * npm Registry vulnerability source
 * Queries npm's bulk advisory endpoint for package vulnerabilities
 */

import type { VulnerabilitySource, IgnoreConfig } from "@repo/core"
import { logger } from "@repo/core"
import { createNpmAuditClient } from "./client.js"
import { createAdvisoryProcessor } from "./processor.js"

// Re-export schemas and types for consumers
export { NpmAuditRequestSchema, NpmAdvisorySchema, NpmAuditResponseSchema } from "./schema.js"

export type { NpmAuditRequest, NpmAdvisory, NpmAuditResponse } from "./schema.js"

// Re-export types
export type { FatalSeverity, NpmSeverity } from "./types.js"

// Re-export processor and client types
export type { NpmAuditClient } from "./client.js"
export type { AdvisoryProcessor } from "./processor.js"

// Re-export factory functions for advanced usage
export { createNpmAuditClient } from "./client.js"
export { createAdvisoryProcessor } from "./processor.js"
export { mapSeverityToLevel, severityToPriority, isCvssScoreFatal } from "./severity.js"

// Re-export constants
export { NPM_AUDIT_API, HTTP, SECURITY, ENV, getConfig } from "./constants.js"

/**
 * Create an npm Registry vulnerability source
 * Queries npm's bulk advisory endpoint for package vulnerabilities
 */
export function createNpmSource(ignoreConfig: IgnoreConfig = {}): VulnerabilitySource {
  const client = createNpmAuditClient()
  const processor = createAdvisoryProcessor(ignoreConfig)

  return {
    name: "npm",

    async scan(packages: Bun.Security.Package[]): Promise<Bun.Security.Advisory[]> {
      if (packages.length === 0) return []

      logger.info(`[npm] Starting scan for ${packages.length} packages`)

      const advisories = await client.queryVulnerabilities(packages)
      const bunAdvisories = processor.processAdvisories(advisories, packages)

      logger.info(`[npm] Scan complete: ${bunAdvisories.length} advisories found`)
      return bunAdvisories
    },
  }
}
