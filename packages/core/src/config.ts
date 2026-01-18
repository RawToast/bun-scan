import { z } from "zod"
import { DEFAULT_SOURCE } from "./types.js"
import { logger } from "./logger.js"
import { ENV, OSV_API } from "./constants.js"

/**
 * Default configuration values
 */
export const CONFIG_DEFAULTS = {
  logLevel: "info" as const,
  bunReportWarnings: true,
  osv: {
    apiBaseUrl: OSV_API.BASE_URL,
    timeoutMs: OSV_API.TIMEOUT_MS,
    disableBatch: false,
  },
  npm: {
    registryUrl: "https://registry.npmjs.org",
    timeoutMs: 30_000,
  },
} as const

/**
 * Schema for package-specific ignore rules
 */
const IgnorePackageRuleSchema = z.object({
  /** Vulnerability IDs to ignore for this package (CVE-*, GHSA-*) */
  vulnerabilities: z.array(z.string()).optional(),
  /** Ignore until this date (ISO 8601 format) - for temporary ignores */
  until: z.string().optional(),
  /** Reason for ignoring (for documentation) */
  reason: z.string().optional(),
})

/**
 * Schema for the ignore configuration file (legacy)
 */
export const IgnoreConfigSchema = z.object({
  /** Vulnerability IDs to ignore globally (CVE-*, GHSA-*) */
  ignore: z.array(z.string()).optional(),
  /** Package-specific ignore rules */
  packages: z.record(z.string(), IgnorePackageRuleSchema).optional(),
})

export type IgnoreConfig = z.infer<typeof IgnoreConfigSchema>

/**
 * Schema for OSV source configuration
 */
const OsvConfigSchema = z.object({
  /** OSV API base URL */
  apiBaseUrl: z.string().optional(),
  /** Request timeout in milliseconds */
  timeoutMs: z.number().optional(),
  /** Disable batch queries (use individual queries) */
  disableBatch: z.boolean().optional(),
})

/**
 * Schema for npm source configuration
 */
const NpmConfigSchema = z.object({
  /** npm registry URL */
  registryUrl: z.string().optional(),
  /** Request timeout in milliseconds */
  timeoutMs: z.number().optional(),
})

/**
 * Schema for the full configuration file including source selection
 */
export const ConfigSchema = z.object({
  /** Vulnerability data source */
  source: z.enum(["osv", "npm", "both"]).catch(DEFAULT_SOURCE).optional(),
  /** Vulnerability IDs to ignore globally (CVE-*, GHSA-*) */
  ignore: z.array(z.string()).optional(),
  /** Package-specific ignore rules */
  packages: z.record(z.string(), IgnorePackageRuleSchema).optional(),
  /** Logging level */
  logLevel: z.enum(["debug", "info", "warn", "error"]).optional(),
  /** Report warnings to Bun (causes install prompt). Set false to print only. */
  bunReportWarnings: z.boolean().optional(),
  /** OSV source configuration */
  osv: OsvConfigSchema.optional(),
  /** npm source configuration */
  npm: NpmConfigSchema.optional(),
})

export type Config = z.infer<typeof ConfigSchema>
export type IgnorePackageRule = z.infer<typeof IgnorePackageRuleSchema>
export type OsvConfig = z.infer<typeof OsvConfigSchema>
export type NpmConfig = z.infer<typeof NpmConfigSchema>

/**
 * Compiled package rule with Set for O(1) vulnerability lookups
 */
export type CompiledPackageRule = {
  vulnerabilitiesSet: Set<string>
  until?: string
  reason?: string
}

/**
 * Compiled ignore config with Sets for O(1) lookups (Issue 2 optimization)
 */
export type CompiledIgnoreConfig = {
  ignoreSet: Set<string>
  packages: Map<string, CompiledPackageRule>
}

/**
 * Compile an IgnoreConfig into a CompiledIgnoreConfig with Set-based lookups
 */
export function compileIgnoreConfig(config: IgnoreConfig): CompiledIgnoreConfig {
  const ignoreSet = new Set(config.ignore ?? [])
  const packages = new Map<string, CompiledPackageRule>()

  for (const [name, rule] of Object.entries(config.packages ?? {})) {
    packages.set(name, {
      vulnerabilitiesSet: new Set(rule.vulnerabilities ?? []),
      until: rule.until,
      reason: rule.reason,
    })
  }

  return { ignoreSet, packages }
}

/**
 * Default config file names to search for (in order of priority)
 */
const CONFIG_FILES = [".bun-scan.json", ".bun-scan.config.json"] as const

/**
 * Parse env string to number, returning undefined if invalid or unset
 */
function parseEnvNumber(envVar: string): number | undefined {
  const value = Bun.env[envVar]
  if (!value) return undefined
  const parsed = Number(value)
  return Number.isNaN(parsed) ? undefined : parsed
}

/**
 * Parse env string to boolean, returning undefined if unset
 * Treats "true" (case-insensitive) as true, "false" as false
 */
function parseEnvBoolean(envVar: string): boolean | undefined {
  const value = Bun.env[envVar]
  if (!value) return undefined
  const lower = value.toLowerCase()
  if (lower === "true") return true
  if (lower === "false") return false
  return undefined
}

/**
 * Parse env string to log level, returning undefined if invalid or unset
 */
function parseEnvLogLevel(envVar: string): Config["logLevel"] | undefined {
  const value = Bun.env[envVar]?.toLowerCase()
  if (!value) return undefined
  if (["debug", "info", "warn", "error"].includes(value)) {
    return value as Config["logLevel"]
  }
  return undefined
}

/**
 * Build configuration from environment variables (fallback layer)
 * These are used when config file values are not set
 */
function buildEnvConfig(): Partial<Config> {
  return {
    logLevel: parseEnvLogLevel(ENV.LOG_LEVEL),
    osv: {
      apiBaseUrl: Bun.env[ENV.API_BASE_URL] || undefined,
      timeoutMs: parseEnvNumber(ENV.TIMEOUT_MS),
      disableBatch: parseEnvBoolean(ENV.DISABLE_BATCH),
    },
    npm: {
      registryUrl: Bun.env["NPM_SCANNER_REGISTRY_URL"] || undefined,
      timeoutMs: parseEnvNumber("NPM_SCANNER_TIMEOUT_MS"),
    },
  }
}

/**
 * Merge configuration layers: defaults → env → config file
 * Config file wins over env, env wins over defaults
 */
function mergeConfig(fileConfig: Config | null): Config {
  const envConfig = buildEnvConfig()

  // Start with defaults
  const merged: Config = {
    source: DEFAULT_SOURCE,
    logLevel: CONFIG_DEFAULTS.logLevel,
    bunReportWarnings: CONFIG_DEFAULTS.bunReportWarnings,
    osv: { ...CONFIG_DEFAULTS.osv },
    npm: { ...CONFIG_DEFAULTS.npm },
  }

  // Layer env values (if set)
  if (envConfig.logLevel !== undefined) merged.logLevel = envConfig.logLevel
  if (envConfig.osv?.apiBaseUrl !== undefined) merged.osv!.apiBaseUrl = envConfig.osv.apiBaseUrl
  if (envConfig.osv?.timeoutMs !== undefined) merged.osv!.timeoutMs = envConfig.osv.timeoutMs
  if (envConfig.osv?.disableBatch !== undefined)
    merged.osv!.disableBatch = envConfig.osv.disableBatch
  if (envConfig.npm?.registryUrl !== undefined) merged.npm!.registryUrl = envConfig.npm.registryUrl
  if (envConfig.npm?.timeoutMs !== undefined) merged.npm!.timeoutMs = envConfig.npm.timeoutMs

  // Layer config file values (if set) - these win
  if (fileConfig) {
    if (fileConfig.source !== undefined) merged.source = fileConfig.source
    if (fileConfig.ignore !== undefined) merged.ignore = fileConfig.ignore
    if (fileConfig.packages !== undefined) merged.packages = fileConfig.packages
    if (fileConfig.logLevel !== undefined) merged.logLevel = fileConfig.logLevel
    if (fileConfig.bunReportWarnings !== undefined)
      merged.bunReportWarnings = fileConfig.bunReportWarnings
    if (fileConfig.osv?.apiBaseUrl !== undefined) merged.osv!.apiBaseUrl = fileConfig.osv.apiBaseUrl
    if (fileConfig.osv?.timeoutMs !== undefined) merged.osv!.timeoutMs = fileConfig.osv.timeoutMs
    if (fileConfig.osv?.disableBatch !== undefined)
      merged.osv!.disableBatch = fileConfig.osv.disableBatch
    if (fileConfig.npm?.registryUrl !== undefined)
      merged.npm!.registryUrl = fileConfig.npm.registryUrl
    if (fileConfig.npm?.timeoutMs !== undefined) merged.npm!.timeoutMs = fileConfig.npm.timeoutMs
  }

  return merged
}

/**
 * Load full configuration from the current working directory
 * Merges: defaults → environment variables → config file
 */
export async function loadConfig(): Promise<Config> {
  for (const filename of CONFIG_FILES) {
    const config = await tryLoadConfigFile(filename)
    if (config) {
      return mergeConfig(config)
    }
  }

  // No config file found - use defaults + env
  return mergeConfig(null)
}

/**
 * Try to load and parse a config file
 */
async function tryLoadConfigFile(filename: string): Promise<Config | null> {
  try {
    const file = Bun.file(filename)
    const exists = await file.exists()

    if (!exists) {
      return null
    }

    const content = await file.json()
    const parsed = ConfigSchema.parse(content)

    logger.info(`Loaded configuration from ${filename}`)
    logConfigStats(parsed)

    return parsed
  } catch (error) {
    if (error instanceof z.ZodError) {
      logger.warn(`Invalid config in ${filename}`, {
        errors: error.issues.map((e) => `${e.path.join(".")}: ${e.message}`),
      })
    } else if (error instanceof SyntaxError) {
      logger.warn(`Failed to parse ${filename} as JSON`, {
        error: error.message,
      })
    }
    // For other errors (file not found, etc.), silently continue
    return null
  }
}

/**
 * Log statistics about the loaded configuration
 */
function logConfigStats(config: Config): void {
  const globalIgnores = config.ignore?.length ?? 0
  const packageRules = Object.keys(config.packages ?? {}).length
  const source = config.source ?? DEFAULT_SOURCE

  if (globalIgnores > 0 || packageRules > 0) {
    logger.info(`Configuration loaded`, {
      source,
      globalIgnores,
      packageRules,
    })
  }
}

/**
 * Check if a vulnerability should be ignored based on the compiled config
 * Uses Set.has() for O(1) lookups instead of Array.includes() O(n)
 */
export function shouldIgnoreVulnerability(
  vulnId: string,
  vulnAliases: string[] | undefined,
  packageName: string | undefined,
  config: CompiledIgnoreConfig,
): { ignored: boolean; reason?: string } {
  // Get all IDs to check (primary ID + aliases)
  const idsToCheck = [vulnId, ...(vulnAliases ?? [])]

  // Check global ignores (O(1) Set lookup)
  for (const id of idsToCheck) {
    if (config.ignoreSet.has(id)) {
      return { ignored: true, reason: `globally ignored (${id})` }
    }
  }

  // Check package-specific ignores
  if (packageName) {
    const rule = config.packages.get(packageName)
    if (rule) {
      // Check if the ignore has expired
      if (rule.until) {
        const untilDate = new Date(rule.until)
        if (untilDate < new Date()) {
          logger.debug(`Ignore rule for ${packageName} expired on ${rule.until}`)
          return { ignored: false }
        }
      }

      // Check package-specific vulnerability ignores (O(1) Set lookup)
      for (const id of idsToCheck) {
        if (rule.vulnerabilitiesSet.has(id)) {
          const reason = rule.reason
            ? `package rule: ${rule.reason}`
            : `ignored for ${packageName} (${id})`
          return { ignored: true, reason }
        }
      }
    }
  }

  return { ignored: false }
}
