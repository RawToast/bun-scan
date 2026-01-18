/**
 * Centralized configuration constants for npm source
 */

import type { FatalSeverity } from "./types.js"

/**
 * npm Audit API Configuration
 */
export const NPM_AUDIT_API = {
  /** Base URL for npm registry */
  REGISTRY_URL: "https://registry.npmjs.org",

  /** Bulk advisory endpoint path */
  BULK_ADVISORY_PATH: "/-/npm/v1/security/advisories/bulk",

  /** Request timeout in milliseconds */
  TIMEOUT_MS: 30_000,

  /** Maximum retry attempts for failed requests */
  MAX_RETRY_ATTEMPTS: 2,

  /** Delay between retry attempts in milliseconds */
  RETRY_DELAY_MS: 1_000,

  /** Maximum packages per request (npm accepts all at once, but we limit for safety) */
  MAX_PACKAGES_PER_REQUEST: 1_000,
} as const

/**
 * HTTP Configuration for npm API
 */
export const HTTP = {
  /** Content type for API requests */
  CONTENT_TYPE: "application/json",

  /** Content encoding for compressed requests */
  CONTENT_ENCODING: "gzip",

  /** User agent for requests */
  USER_AGENT: "@bun-security-scanner/npm/1.0.0",
} as const

/**
 * Security Configuration
 */
export const SECURITY = {
  /** CVSS score threshold for fatal advisories */
  CVSS_FATAL_THRESHOLD: 7.0,

  /** npm severity levels that map to fatal level */
  FATAL_SEVERITIES: ["critical", "high"] as const satisfies readonly FatalSeverity[],

  /** Maximum vulnerabilities to process per package */
  MAX_VULNERABILITIES_PER_PACKAGE: 100,

  /** Maximum length for vulnerability descriptions */
  MAX_DESCRIPTION_LENGTH: 200,
} as const

/**
 * Environment variable configuration
 */
export const ENV = {
  /** Custom registry URL override */
  REGISTRY_URL: "NPM_SCANNER_REGISTRY_URL",

  /** Custom timeout override */
  TIMEOUT_MS: "NPM_SCANNER_TIMEOUT_MS",
} as const

/**
 * Get configuration value with environment variable override
 */
export function getConfig<T>(envVar: string, defaultValue: T, parser?: (value: string) => T): T {
  const envValue = Bun.env[envVar]
  if (!envValue) return defaultValue

  if (parser) {
    try {
      return parser(envValue)
    } catch {
      return defaultValue
    }
  }

  // Type-safe parsing for common types
  if (typeof defaultValue === "number") {
    const parsed = Number(envValue)
    return (Number.isNaN(parsed) ? defaultValue : parsed) as T
  }

  if (typeof defaultValue === "boolean") {
    return (envValue.toLowerCase() === "true") as T
  }

  return envValue as T
}
