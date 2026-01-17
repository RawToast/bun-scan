/**
 * npm Registry vulnerability source
 * Queries npm's bulk advisory endpoint for package vulnerabilities
 */

import type { VulnerabilitySource } from "../types.js"
import type { IgnoreConfig } from "../../config.js"
import { NpmAuditClient } from "./client.js"
import { AdvisoryProcessor } from "./processor.js"
import { logger } from "../../logger.js"

export class NpmSource implements VulnerabilitySource {
  readonly name = "npm"
  private readonly client: NpmAuditClient
  private readonly processor: AdvisoryProcessor

  constructor(ignoreConfig: IgnoreConfig) {
    this.client = new NpmAuditClient()
    this.processor = new AdvisoryProcessor(ignoreConfig)
  }

  async scan(packages: Bun.Security.Package[]): Promise<Bun.Security.Advisory[]> {
    if (packages.length === 0) return []

    logger.info(`[npm] Starting scan for ${packages.length} packages`)

    const advisories = await this.client.queryVulnerabilities(packages)
    const bunAdvisories = this.processor.processAdvisories(advisories, packages)

    logger.info(`[npm] Scan complete: ${bunAdvisories.length} advisories found`)
    return bunAdvisories
  }
}
