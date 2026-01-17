// Bun Security Scanner API types
// These will be moved to @types/bun when officially released

// OSV API related types
export type FatalSeverity = "CRITICAL" | "HIGH"

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
