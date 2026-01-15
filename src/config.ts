import { z } from "zod"
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
 * Schema for the ignore configuration file
 */
export const IgnoreConfigSchema = z.object({
  /** Vulnerability IDs to ignore globally (CVE-*, GHSA-*) */
  ignore: z.array(z.string()).optional(),
  /** Package-specific ignore rules */
  packages: z.record(z.string(), IgnorePackageRuleSchema).optional(),
})

export type IgnoreConfig = z.infer<typeof IgnoreConfigSchema>
export type IgnorePackageRule = z.infer<typeof IgnorePackageRuleSchema>

/**
 * Default config file names to search for (in order of priority)
 */
const CONFIG_FILES = [".bun-scan.json", ".bun-scan.config.json"] as const

/**
 * Load ignore configuration from the current working directory
 */
export async function loadIgnoreConfig(): Promise<IgnoreConfig> {
  for (const filename of CONFIG_FILES) {
    const config = await tryLoadConfigFile(filename)
    if (config) {
      return config
    }
  }

  // No config file found - return empty config
  return {}
}

/**
 * Try to load and parse a config file
 */
async function tryLoadConfigFile(filename: string): Promise<IgnoreConfig | null> {
  try {
    const file = Bun.file(filename)
    const exists = await file.exists()

    if (!exists) {
      return null
    }

    const content = await file.json()
    const parsed = IgnoreConfigSchema.parse(content)

    logger.info(`Loaded ignore configuration from ${filename}`)
    logIgnoreStats(parsed)

    return parsed
  } catch (error) {
    if (error instanceof z.ZodError) {
      logger.warn(`Invalid ignore config in ${filename}`, {
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
 * Log statistics about the loaded ignore configuration
 */
function logIgnoreStats(config: IgnoreConfig): void {
  const globalIgnores = config.ignore?.length ?? 0
  const packageRules = Object.keys(config.packages ?? {}).length

  if (globalIgnores > 0 || packageRules > 0) {
    logger.info(`Ignore rules loaded`, {
      globalIgnores,
      packageRules,
    })
  }
}

/**
 * Check if a vulnerability should be ignored based on the config
 */
export function shouldIgnoreVulnerability(
  vulnId: string,
  vulnAliases: string[] | undefined,
  packageName: string | undefined,
  config: IgnoreConfig,
): { ignored: boolean; reason?: string } {
  // Get all IDs to check (primary ID + aliases)
  const idsToCheck = [vulnId, ...(vulnAliases ?? [])]

  // Check global ignores
  if (config.ignore) {
    for (const id of idsToCheck) {
      if (config.ignore.includes(id)) {
        return { ignored: true, reason: `globally ignored (${id})` }
      }
    }
  }

  // Check package-specific ignores
  if (packageName && config.packages?.[packageName]) {
    const rule = config.packages[packageName]

    // Check if the ignore has expired
    if (rule.until) {
      const untilDate = new Date(rule.until)
      if (untilDate < new Date()) {
        logger.debug(`Ignore rule for ${packageName} expired on ${rule.until}`)
        return { ignored: false }
      }
    }

    // Check package-specific vulnerability ignores
    if (rule.vulnerabilities) {
      for (const id of idsToCheck) {
        if (rule.vulnerabilities.includes(id)) {
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
