/// <reference types="bun-types" />

// Bun Security Scanner API types
// These will be moved to @types/bun when officially released

// OSV API related types
export type FatalSeverity = "CRITICAL" | "HIGH"

/**
 * Extended advisory returned by bun-scan sources.
 * Bun's Security.Advisory only requires level/package/url/description;
 * we also carry id, message, and aliases for deduplication and logging.
 */
export type SecurityAdvisory = Bun.Security.Advisory & {
  id: string
  message: string
  aliases: string[]
}

/**
 * Common interface for vulnerability data sources
 * Abstracts the differences between OSV.dev and npm Registry APIs
 */
export interface VulnerabilitySource {
  /** Source identifier for logging */
  readonly name: string

  /**
   * Scan packages for vulnerabilities
   * Each source implements its own API logic internally
   */
  scan(packages: Bun.Security.Package[]): Promise<SecurityAdvisory[]>
}

/** Supported vulnerability source identifiers */
export type SourceType = "osv" | "npm" | "both"

/** Default source when not specified in config */
export const DEFAULT_SOURCE: SourceType = "osv"
