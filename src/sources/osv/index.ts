import type { VulnerabilitySource } from "../types.js"
import type { IgnoreConfig } from "../../config.js"
import { OSVClient } from "./client.js"
import { VulnerabilityProcessor } from "./processor.js"
import { logger } from "../../logger.js"

/**
 * OSV.dev vulnerability source
 * Queries Google's OSV database for npm package vulnerabilities
 */
export class OSVSource implements VulnerabilitySource {
  readonly name = "osv"
  private readonly client: OSVClient
  private readonly processor: VulnerabilityProcessor

  constructor(ignoreConfig: IgnoreConfig) {
    this.client = new OSVClient()
    this.processor = new VulnerabilityProcessor(ignoreConfig)
  }

  async scan(packages: Bun.Security.Package[]): Promise<Bun.Security.Advisory[]> {
    logger.info(`[OSV] Starting scan for ${packages.length} packages`)

    const vulnerabilities = await this.client.queryVulnerabilities(packages)
    const advisories = this.processor.processVulnerabilities(vulnerabilities, packages)

    logger.info(`[OSV] Scan complete: ${advisories.length} advisories found`)
    return advisories
  }
}
