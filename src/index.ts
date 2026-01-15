/// <reference types="bun-types" />
import "./types.js"
import { OSVClient } from "./client.js"
import { VulnerabilityProcessor } from "./processor.js"
import { logger } from "./logger.js"
import { loadIgnoreConfig } from "./config.js"

/**
 * Bun Security Scanner for OSV.dev vulnerability detection
 * Integrates with Google's OSV database to detect vulnerabilities in npm packages
 */
export const scanner: Bun.Security.Scanner = {
  version: "1", // This is the version of Bun security scanner implementation. You should keep this set as '1'

  async scan({ packages }) {
    try {
      logger.info(`Starting OSV scan for ${packages.length} packages`)

      // Load ignore configuration
      const ignoreConfig = await loadIgnoreConfig()

      // Initialize components
      const client = new OSVClient()
      const processor = new VulnerabilityProcessor(ignoreConfig)

      // Fetch vulnerabilities from OSV.dev
      const vulnerabilities = await client.queryVulnerabilities(packages)

      // Process vulnerabilities into security advisories
      const advisories = processor.processVulnerabilities(vulnerabilities, packages)

      logger.info(
        `OSV scan completed: ${advisories.length} advisories found for ${packages.length} packages`,
      )

      return advisories
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      logger.error("OSV scanner encountered an unexpected error", {
        error: message,
      })

      // Fail-safe: allow installation to proceed on scanner errors
      return []
    }
  },
}

// CLI entry point
if (import.meta.main) {
  const { runCli } = await import("./cli.js")
  await runCli()
}
