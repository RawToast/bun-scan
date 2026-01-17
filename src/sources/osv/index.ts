import type { VulnerabilitySource } from "../types.js"
import type { IgnoreConfig } from "../../config.js"
import { createOSVClient } from "./client.js"
import { createVulnerabilityProcessor } from "./processor.js"
import { logger } from "../../logger.js"

/**
 * Create an OSV.dev vulnerability source
 * Queries Google's OSV database for npm package vulnerabilities
 */
export function createOSVSource(ignoreConfig: IgnoreConfig): VulnerabilitySource {
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
