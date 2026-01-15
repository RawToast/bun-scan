/**
 * Centralized configuration constants for OSV Scanner
 * All magic numbers and configuration values consolidated here
 */

import type { FatalSeverity } from "./types.js"

/**
 * OSV API Configuration
 */
export const OSV_API = {
  /** Base URL for OSV API */
  BASE_URL: "https://api.osv.dev/v1",

  /** Request timeout in milliseconds */
  TIMEOUT_MS: 30_000,

  /** Maximum packages per batch query */
  MAX_BATCH_SIZE: 1_000,

  /** Maximum retry attempts for failed requests */
  MAX_RETRY_ATTEMPTS: 2,

  /** Delay between retry attempts in milliseconds */
  RETRY_DELAY_MS: 1_000,

  /** Default ecosystem for npm packages */
  DEFAULT_ECOSYSTEM: "npm",
} as const

/**
 * HTTP Configuration
 */
export const HTTP = {
  /** Content type for API requests */
  CONTENT_TYPE: "application/json",

  /** User agent for requests */
  USER_AGENT: "bun-osv-scanner/1.0.0",
} as const

/**
 * Security Configuration
 */
export const SECURITY = {
  /** CVSS score threshold for fatal advisories */
  CVSS_FATAL_THRESHOLD: 7.0,

  /** Database severities that map to fatal level */
  FATAL_SEVERITIES: ["CRITICAL", "HIGH"] as const satisfies readonly FatalSeverity[],

  /** Maximum vulnerabilities to process per package */
  MAX_VULNERABILITIES_PER_PACKAGE: 100,

  /** Maximum length for vulnerability descriptions */
  MAX_DESCRIPTION_LENGTH: 200,
} as const

/**
 * Performance Configuration
 */
export const PERFORMANCE = {
  /** Enable batch queries for better performance */
  USE_BATCH_QUERIES: true,

  /** Maximum concurrent vulnerability detail requests */
  MAX_CONCURRENT_DETAILS: 10,

  /** Maximum response size in bytes (32MB) */
  MAX_RESPONSE_SIZE: 32 * 1024 * 1024,
} as const

/**
 * Environment variable configuration
 */
export const ENV = {
  /** Log level environment variable */
  LOG_LEVEL: "OSV_LOG_LEVEL",

  /** Custom API base URL override */
  API_BASE_URL: "OSV_API_BASE_URL",

  /** Custom timeout override */
  TIMEOUT_MS: "OSV_TIMEOUT_MS",

  /** Disable batch queries */
  DISABLE_BATCH: "OSV_DISABLE_BATCH",
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
