/// <reference types="bun-types" />
import "./types.js"
import { loadConfig } from "./config.js"
import { createSources } from "./sources/factory.js"
import { createMultiSourceScanner } from "./sources/multi.js"
import { logger } from "./logger.js"

/**
 * Bun Security Scanner with configurable vulnerability sources
 * Supports OSV.dev, npm Registry, or both
 */
export const scanner: Bun.Security.Scanner = {
  version: "1",

  async scan({ packages }) {
    try {
      logger.info(`Starting vulnerability scan for ${packages.length} packages`)

      // Load configuration (includes source and ignore rules)
      const config = await loadConfig()

      // Create vulnerability sources based on config
      const sources = createSources(config.source ?? "osv", config)

      // Scan with all configured sources
      const multiScanner = createMultiSourceScanner(sources)
      const advisories = await multiScanner.scan(packages)

      logger.info(
        `Scan completed: ${advisories.length} advisories found for ${packages.length} packages`,
      )

      return advisories
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      logger.error("Scanner encountered an unexpected error", {
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
