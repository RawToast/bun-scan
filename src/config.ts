import { z } from "zod"
import { DEFAULT_SOURCE } from "./sources/types.js"
import { logger } from "./logger.js"

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
 * Schema for the full configuration file including source selection
 */
export const ConfigSchema = z.object({
  /** Vulnerability data source */
  source: z.enum(["osv", "npm", "both"]).catch(DEFAULT_SOURCE).optional(),
  /** Vulnerability IDs to ignore globally (CVE-*, GHSA-*) */
  ignore: z.array(z.string()).optional(),
  /** Package-specific ignore rules */
  packages: z.record(z.string(), IgnorePackageRuleSchema).optional(),
})

export type Config = z.infer<typeof ConfigSchema>
export type IgnorePackageRule = z.infer<typeof IgnorePackageRuleSchema>

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
 * Load full configuration from the current working directory
 */
export async function loadConfig(): Promise<Config> {
  for (const filename of CONFIG_FILES) {
    const config = await tryLoadConfigFile(filename)
    if (config) {
      return { source: DEFAULT_SOURCE, ...config }
    }
  }

  // No config file found - return default config
  return { source: DEFAULT_SOURCE }
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
