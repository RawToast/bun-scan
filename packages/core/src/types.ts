/// <reference types="bun-types" />

// Bun Security Scanner API types
// These will be moved to @types/bun when officially released

// OSV API related types
export type FatalSeverity = "CRITICAL" | "HIGH"

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

// Extend global Bun namespace with missing types
declare global {
  namespace Bun {
    // Bun.semver types (missing from current bun-types)
    namespace semver {
      function satisfies(version: string, range: string): boolean
    }

    // Augment Bun.Security.Advisory with missing properties
    namespace Security {
      interface Advisory {
        id: string
        message: string
        /** Aliases (CVEs, GHSAs) for deduplication across sources */
        aliases?: string[]
      }
    }
  }
}
