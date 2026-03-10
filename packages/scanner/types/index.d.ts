/// <reference types="bun-types" />
import type { z } from "zod"

// ============================================================================
// Core Types (from @repo/core)
// ============================================================================

/** Severity levels that cause fatal exit (block install) */
export type FatalSeverity = "CRITICAL" | "HIGH"

/** Supported vulnerability source identifiers */
export type SourceType = "osv" | "npm" | "both"

/** Default source when not specified in config */
export declare const DEFAULT_SOURCE: SourceType

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

// ============================================================================
// Logger Types (from @repo/core)
// ============================================================================

export type LogLevel = "debug" | "info" | "warn" | "error"
export type LogContext = Record<string, unknown>

export interface Logger {
  debug(message: string, context?: LogContext): void
  info(message: string, context?: LogContext): void
  warn(message: string, context?: LogContext): void
  error(message: string, context?: LogContext): void
}

/** Create a logger with specific log level */
export declare function createLogger(level?: LogLevel): Logger

/** Default logger instance */
export declare const logger: Logger

// ============================================================================
// Retry Types (from @repo/core)
// ============================================================================

export interface RetryConfig {
  maxAttempts: number
  delayMs: number
  shouldRetry?: (error: Error) => boolean
}

export declare const DEFAULT_RETRY_CONFIG: RetryConfig

export declare function withRetry<T>(
  operation: () => Promise<T>,
  operationName: string,
  config?: RetryConfig,
): Promise<T>

// ============================================================================
// Config Types (from @repo/core)
// ============================================================================

export interface IgnorePackageRule {
  vulnerabilities?: string[]
  until?: string
  reason?: string
}

export interface IgnoreConfig {
  ignore?: string[]
  packages?: Record<string, IgnorePackageRule>
}

export interface Config {
  source?: SourceType
  ignore?: string[]
  packages?: Record<string, IgnorePackageRule>
  logLevel?: "debug" | "info" | "warn" | "error"
  bunReportWarnings?: boolean
  /** Fail on scanner errors (block install). Env var overrides config file (escape hatch). */
  failOnScannerError?: boolean
  osv?: OsvConfig
  npm?: NpmConfig
}

export interface OsvConfig {
  apiBaseUrl?: string
  timeoutMs?: number
  disableBatch?: boolean
}

export interface NpmConfig {
  registryUrl?: string
  timeoutMs?: number
}

export interface CreateOSVSourceOptions {
  ignore?: IgnoreConfig
  osv?: OsvConfig
  /** When true, throw on internal errors (batch/query failures) instead of continuing with partial results */
  failOnScannerError?: boolean
}

export interface CreateNpmSourceOptions {
  ignore?: IgnoreConfig
  npm?: NpmConfig
  /** When true, throw on internal errors (batch/query failures) instead of continuing with partial results */
  failOnScannerError?: boolean
}

export interface CompiledPackageRule {
  vulnerabilitiesSet: Set<string>
  until?: string
  reason?: string
}

export interface CompiledIgnoreConfig {
  ignoreSet: Set<string>
  packages: Map<string, CompiledPackageRule>
}

export interface ConfigDefaults {
  readonly logLevel: "debug" | "info" | "warn" | "error"
  readonly bunReportWarnings: boolean
  readonly failOnScannerError: boolean
  readonly osv: {
    readonly apiBaseUrl: string
    readonly timeoutMs: number
    readonly disableBatch: boolean
  }
  readonly npm: {
    readonly registryUrl: string
    readonly timeoutMs: number
  }
}

/** Default configuration values */
export declare const CONFIG_DEFAULTS: ConfigDefaults

/** Zod schema for ignore config validation */
export declare const IgnoreConfigSchema: z.ZodObject<{
  ignore: z.ZodOptional<z.ZodArray<z.ZodString>>
  packages: z.ZodOptional<
    z.ZodRecord<
      z.ZodString,
      z.ZodObject<{
        vulnerabilities: z.ZodOptional<z.ZodArray<z.ZodString>>
        until: z.ZodOptional<z.ZodString>
        reason: z.ZodOptional<z.ZodString>
      }>
    >
  >
}>

/** Zod schema for full config validation */
export declare const ConfigSchema: z.ZodObject<{
  source: z.ZodOptional<z.ZodCatch<z.ZodEnum<["osv", "npm", "both"]>>>
  ignore: z.ZodOptional<z.ZodArray<z.ZodString>>
  packages: z.ZodOptional<
    z.ZodRecord<
      z.ZodString,
      z.ZodObject<{
        vulnerabilities: z.ZodOptional<z.ZodArray<z.ZodString>>
        until: z.ZodOptional<z.ZodString>
        reason: z.ZodOptional<z.ZodString>
      }>
    >
  >
  logLevel: z.ZodOptional<z.ZodEnum<["debug", "info", "warn", "error"]>>
  bunReportWarnings: z.ZodOptional<z.ZodBoolean>
  failOnScannerError: z.ZodOptional<z.ZodBoolean>
  osv: z.ZodOptional<
    z.ZodObject<{
      apiBaseUrl: z.ZodOptional<z.ZodString>
      timeoutMs: z.ZodOptional<z.ZodNumber>
      disableBatch: z.ZodOptional<z.ZodBoolean>
    }>
  >
  npm: z.ZodOptional<
    z.ZodObject<{
      registryUrl: z.ZodOptional<z.ZodString>
      timeoutMs: z.ZodOptional<z.ZodNumber>
    }>
  >
}>

/** Load config from .bun-scan.json or .bun-scan.config.json */
export declare function loadConfig(): Promise<Config>

/** Compile ignore config for efficient lookups */
export declare function compileIgnoreConfig(config: IgnoreConfig): CompiledIgnoreConfig

/** Check if a vulnerability should be ignored */
export declare function shouldIgnoreVulnerability(
  vulnId: string,
  vulnAliases: string[] | undefined,
  packageName: string | undefined,
  config: CompiledIgnoreConfig,
): { ignored: boolean; reason?: string }

// ============================================================================
// Source Factories
// ============================================================================

/** Create an OSV.dev vulnerability source */
export declare function createOSVSource(
  config?: CreateOSVSourceOptions | IgnoreConfig,
): VulnerabilitySource

/** Create an npm audit vulnerability source */
export declare function createNpmSource(
  options?: CreateNpmSourceOptions | IgnoreConfig,
): VulnerabilitySource

/** Create a vulnerability source by type */
export declare function createSource(
  type: "osv" | "npm",
  config: Config,
  failOnScannerError?: boolean,
): VulnerabilitySource

/** Create all sources for a given type (both = OSV + npm) */
export declare function createSources(
  type: SourceType,
  config: Config,
  failOnScannerError?: boolean,
): VulnerabilitySource[]

// ============================================================================
// Multi-Source Scanner
// ============================================================================

export interface MultiSourceScanner {
  scan(packages: Bun.Security.Package[]): Promise<Bun.Security.Advisory[]>
}

/** Options for multi-source scanner */
export interface MultiSourceScannerOptions {
  /** When true, throw if any configured source fails */
  failOnScannerError?: boolean
}

/** Create a scanner that queries multiple sources in parallel */
export declare function createMultiSourceScanner(
  sources: VulnerabilitySource[],
  options?: MultiSourceScannerOptions,
): MultiSourceScanner

// ============================================================================
// Main Scanner Export
// ============================================================================

/**
 * Bun Security Scanner with configurable vulnerability sources
 * Supports OSV.dev, npm Registry, or both
 */
export declare const scanner: Bun.Security.Scanner

// ============================================================================
// Global Augmentations (for Bun types)
// ============================================================================

declare global {
  namespace Bun {
    namespace semver {
      function satisfies(version: string, range: string): boolean
    }

    namespace Security {
      interface Advisory {
        id: string
        message: string
        aliases?: string[]
      }
    }
  }
}
