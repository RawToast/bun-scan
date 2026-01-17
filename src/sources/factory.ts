import type { VulnerabilitySource, SourceType } from "./types.js"
import type { IgnoreConfig } from "../config.js"
import { OSVSource } from "./osv/index.js"
import { NpmSource } from "./npm/index.js"

/**
 * Create a single vulnerability source by type
 */
export function createSource(type: "osv" | "npm", ignoreConfig: IgnoreConfig): VulnerabilitySource {
  switch (type) {
    case "osv":
      return new OSVSource(ignoreConfig)
    case "npm":
      return new NpmSource(ignoreConfig)
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
      return [new OSVSource(ignoreConfig)]
    case "npm":
      return [new NpmSource(ignoreConfig)]
    case "both":
      return [new OSVSource(ignoreConfig), new NpmSource(ignoreConfig)]
    default:
      throw new Error(`Unknown source type: ${type}`)
  }
}
