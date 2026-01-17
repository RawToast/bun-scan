/**
 * npm Registry vulnerability source
 * Queries npm's bulk advisory endpoint for package vulnerabilities
 */

import type { VulnerabilitySource } from "../types.js"
import type { IgnoreConfig } from "../../config.js"
import { createNpmAuditClient } from "./client.js"
import { createAdvisoryProcessor } from "./processor.js"
import { logger } from "../../logger.js"

/**
 * Create an npm Registry vulnerability source
 * Queries npm's bulk advisory endpoint for package vulnerabilities
 */
export function createNpmSource(ignoreConfig: IgnoreConfig): VulnerabilitySource {
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
