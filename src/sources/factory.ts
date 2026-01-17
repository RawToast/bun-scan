import type { VulnerabilitySource, SourceType } from "./types.js"
import type { IgnoreConfig } from "../config.js"
import { createOSVSource } from "./osv/index.js"
import { createNpmSource } from "./npm/index.js"

/**
 * Create a single vulnerability source by type
 */
export function createSource(type: "osv" | "npm", ignoreConfig: IgnoreConfig): VulnerabilitySource {
  switch (type) {
    case "osv":
      return createOSVSource(ignoreConfig)
    case "npm":
      return createNpmSource(ignoreConfig)
    default:
      throw new Error(`Unknown source type: ${type}`)
  }
}

/**
 * Create vulnerability sources based on config
 * Returns array to support 'both' mode
 */
export function createSources(type: SourceType, ignoreConfig: IgnoreConfig): VulnerabilitySource[] {
  switch (type) {
    case "osv":
      return [createOSVSource(ignoreConfig)]
    case "npm":
      return [createNpmSource(ignoreConfig)]
    case "both":
      return [createOSVSource(ignoreConfig), createNpmSource(ignoreConfig)]
    default:
      throw new Error(`Unknown source type: ${type}`)
  }
}
