/// <reference types="bun-types" />
import "@repo/core"
import { loadConfig, logger, CONFIG_DEFAULTS } from "@repo/core"
import { createSources } from "./sources/factory.js"
import { createMultiSourceScanner } from "./sources/multi.js"

// Re-export types and utilities from core for programmatic users
export type {
  Config,
  IgnoreConfig,
  IgnorePackageRule,
  FatalSeverity,
  SourceType,
  VulnerabilitySource,
  Logger,
  LogLevel,
  LogContext,
  RetryConfig,
  OsvConfig,
  NpmConfig,
} from "@repo/core"

export {
  loadConfig,
  ConfigSchema,
  IgnoreConfigSchema,
  compileIgnoreConfig,
  shouldIgnoreVulnerability,
  logger,
  createLogger,
  withRetry,
  DEFAULT_RETRY_CONFIG,
  DEFAULT_SOURCE,
  CONFIG_DEFAULTS,
} from "@repo/core"

// Re-export source factories for advanced usage
export { createOSVSource } from "@repo/source-osv"
export { createNpmSource } from "@repo/source-npm"

// Export scanner-specific utilities
export { createSource, createSources } from "./sources/factory.js"
export { createMultiSourceScanner } from "./sources/multi.js"
export type { MultiSourceScanner } from "./sources/multi.js"

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
      const bunReportWarnings = config.bunReportWarnings ?? CONFIG_DEFAULTS.bunReportWarnings

      // Create vulnerability sources based on config
      const sources = createSources(config.source ?? "osv", config)

      // Scan with all configured sources
      const multiScanner = createMultiSourceScanner(sources)
      const advisories = await multiScanner.scan(packages)

      logger.info(
        `Scan completed: ${advisories.length} advisories found for ${packages.length} packages`,
      )

      // Filter warnings if bunReportWarnings is false
      if (!bunReportWarnings) {
        const warnings = advisories.filter((a) => a.level === "warn")
        const fatals = advisories.filter((a) => a.level === "fatal")

        if (warnings.length > 0) {
          // Print warnings but don't report to bun (no prompt)
          for (const warning of warnings) {
            logger.warn(`[ADVISORY] ${warning.package}: ${warning.message}`, {
              id: warning.id,
              level: warning.level,
            })
          }
          logger.info(
            `${warnings.length} warning-level advisories printed (not reported to bun due to bunReportWarnings=false)`,
          )
        }

        // Only return fatal advisories to bun
        return fatals
      }

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
