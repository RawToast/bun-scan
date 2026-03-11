import type { VulnerabilitySource, SourceType, Config, IgnoreConfig } from "@repo/core"
import { createOSVSource } from "@repo/source-osv"
import { createNpmSource } from "@repo/source-npm"

/**
 * Extract ignore config from full config
 */
function extractIgnoreConfig(config: Config): IgnoreConfig {
  return { ignore: config.ignore, packages: config.packages }
}

/**
 * Create a single vulnerability source by type
 */
export function createSource(
  type: "osv" | "npm",
  config: Config,
  failOnScannerError?: boolean,
): VulnerabilitySource {
  const ignoreConfig = extractIgnoreConfig(config)

  switch (type) {
    case "osv":
      return createOSVSource({ ignore: ignoreConfig, osv: config.osv, failOnScannerError })
    case "npm":
      return createNpmSource({ ignore: ignoreConfig, npm: config.npm, failOnScannerError })
    default:
      throw new Error(`Unknown source type: ${type}`)
  }
}

/**
 * Create vulnerability sources based on config
 * Returns array to support 'both' mode
 */
export function createSources(
  type: SourceType,
  config: Config,
  failOnScannerError?: boolean,
): VulnerabilitySource[] {
  const ignoreConfig = extractIgnoreConfig(config)

  switch (type) {
    case "osv":
      return [createOSVSource({ ignore: ignoreConfig, osv: config.osv, failOnScannerError })]
    case "npm":
      return [createNpmSource({ ignore: ignoreConfig, npm: config.npm, failOnScannerError })]
    case "both":
      return [
        createOSVSource({ ignore: ignoreConfig, osv: config.osv, failOnScannerError }),
        createNpmSource({ ignore: ignoreConfig, npm: config.npm, failOnScannerError }),
      ]
    default:
      throw new Error(`Unknown source type: ${type}`)
  }
}
