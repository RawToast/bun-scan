import type { VulnerabilitySource, IgnoreConfig } from "@repo/core"
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
export type { OSVClient } from "./client.js"
export type { VulnerabilityProcessor } from "./processor.js"

// Re-export factory functions for advanced usage
export { createOSVClient } from "./client.js"
export { createVulnerabilityProcessor } from "./processor.js"
export { mapSeverityToLevel } from "./severity.js"
export { isPackageAffected } from "./semver.js"

/**
 * Create an OSV.dev vulnerability source
 * Queries Google's OSV database for npm package vulnerabilities
 */
export function createOSVSource(ignoreConfig: IgnoreConfig = {}): VulnerabilitySource {
  const client = createOSVClient()
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
