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
  scan(packages: Bun.Security.Package[]): Promise<Bun.Security.Advisory[]>
}

/** Supported vulnerability source identifiers */
export type SourceType = "osv" | "npm" | "both"

/** Default source when not specified in config */
export const DEFAULT_SOURCE: SourceType = "osv"
