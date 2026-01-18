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
  config?: Partial<RetryConfig>,
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
}

export interface OsvConfig {
  apiBaseUrl?: string
  timeoutMs?: number
  disableBatch?: boolean
}

export interface CreateOSVSourceOptions {
  ignore?: IgnoreConfig
  osv?: OsvConfig
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
}>

/** Load config from .bun-scan.json or .bun-scan.config.json */
export declare function loadConfig(): Promise<Config>

/** Compile ignore config for efficient lookups */
export declare function compileIgnoreConfig(config: IgnoreConfig): CompiledIgnoreConfig

/** Check if a vulnerability should be ignored */
export declare function shouldIgnoreVulnerability(
  compiledConfig: CompiledIgnoreConfig,
  vulnId: string,
  packageName: string,
  aliases?: string[],
): boolean

// ============================================================================
// Source Factories
// ============================================================================

/** Create an OSV.dev vulnerability source */
export declare function createOSVSource(
  config?: CreateOSVSourceOptions | IgnoreConfig,
): VulnerabilitySource

/** Create an npm audit vulnerability source */
export declare function createNpmSource(config?: IgnoreConfig): VulnerabilitySource

/** Create a vulnerability source by type */
export declare function createSource(type: SourceType, config?: IgnoreConfig): VulnerabilitySource

/** Create all sources for a given type (both = OSV + npm) */
export declare function createSources(
  type: SourceType,
  config?: IgnoreConfig,
): VulnerabilitySource[]

// ============================================================================
// Multi-Source Scanner
// ============================================================================

export interface MultiSourceScanner {
  scan(packages: Bun.Security.Package[]): Promise<Bun.Security.Advisory[]>
}

/** Create a scanner that queries multiple sources in parallel */
export declare function createMultiSourceScanner(sources: VulnerabilitySource[]): MultiSourceScanner

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
