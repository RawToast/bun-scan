import type { OSVVulnerability } from "./schema.js"
import { isPackageAffected } from "./semver.js"
import { mapSeverityToLevel } from "./severity.js"
import { SECURITY } from "../../constants.js"
import { logger } from "../../logger.js"
import {
  type IgnoreConfig,
  type CompiledIgnoreConfig,
  compileIgnoreConfig,
  shouldIgnoreVulnerability,
} from "../../config.js"

/** Hostname regex for URL parsing - avoids expensive new URL() calls */
const HOSTNAME_REGEX = /^https?:\/\/([^/:?#]+)(?::\d+)?(?:[/?#]|$)/

/** Known CVE reference hosts for prioritization */
const CVE_HOSTS = new Set(["cve.mitre.org", "nvd.nist.gov"])

/** Vulnerability Processor interface */
export interface VulnerabilityProcessor {
  processVulnerabilities(
    vulnerabilities: OSVVulnerability[],
    packages: Bun.Security.Package[],
  ): Bun.Security.Advisory[]
}

/**
 * Create a vulnerability processor
 * Handles vulnerability-to-package matching and advisory generation
 */
export function createVulnerabilityProcessor(
  ignoreConfig: IgnoreConfig = {},
): VulnerabilityProcessor {
  const compiledIgnoreConfig = compileIgnoreConfig(ignoreConfig)
  let ignoredCount = 0

  /**
   * Get the best URL to reference for this vulnerability
   * Prioritizes official references and known vulnerability databases
   */
  function getVulnerabilityUrl(vuln: OSVVulnerability): string | null {
    if (!vuln.references || vuln.references.length === 0) {
      return null
    }

    // Prioritize official advisory URLs
    const advisoryRef = vuln.references.find(
      (ref) => ref.type === "ADVISORY" || ref.url.includes("github.com/advisories"),
    )
    if (advisoryRef) {
      return advisoryRef.url
    }

    // Then CVE URLs (Issue 3 optimization: regex instead of new URL())
    const cveRef = vuln.references.find((ref) => {
      const match = ref.url.match(HOSTNAME_REGEX)
      const hostname = match?.[1]?.toLowerCase()
      return hostname ? CVE_HOSTS.has(hostname) : false
    })
    if (cveRef) {
      return cveRef.url
    }

    // Fall back to first reference
    return vuln.references[0]?.url || null
  }

  /**
   * Get a descriptive summary of the vulnerability
   * Uses summary, details, or fallback description
   */
  function getVulnerabilityDescription(vuln: OSVVulnerability): string | null {
    // Prefer concise summary
    if (vuln.summary?.trim()) {
      return vuln.summary.trim()
    }

    // Fall back to details (truncated if too long)
    if (vuln.details?.trim()) {
      const details = vuln.details.trim()
      if (details.length <= SECURITY.MAX_DESCRIPTION_LENGTH) {
        return details
      }
      // Truncate long details to first sentence or max length
      const firstSentence = details.match(/^[^.!?]*[.!?]/)?.[0]
      if (firstSentence && firstSentence.length <= SECURITY.MAX_DESCRIPTION_LENGTH) {
        return firstSentence
      }
      return `${details.substring(0, SECURITY.MAX_DESCRIPTION_LENGTH - 3)}...`
    }

    // No description available
    return null
  }

  /**
   * Create a Bun security advisory from an OSV vulnerability and affected package
   */
  function createAdvisory(
    vuln: OSVVulnerability,
    pkg: Bun.Security.Package,
  ): Bun.Security.Advisory {
    const level = mapSeverityToLevel(vuln)
    const url = getVulnerabilityUrl(vuln)
    const description = getVulnerabilityDescription(vuln)

    return {
      id: vuln.id,
      message: vuln.summary || vuln.details || vuln.id,
      level,
      package: pkg.name,
      url,
      description,
    }
  }

  /**
   * Process a single vulnerability against matching packages only
   * Uses pre-built package index for O(1) name lookup instead of O(n) iteration
   */
  function processVulnerability(
    vuln: OSVVulnerability,
    packagesByName: Map<string, Bun.Security.Package[]>,
    processedPairs: Set<string>,
    compiledConfig: CompiledIgnoreConfig,
  ): Bun.Security.Advisory[] {
    const advisories: Bun.Security.Advisory[] = []

    if (!vuln.affected) {
      logger.debug(`Vulnerability ${vuln.id} has no affected packages`)
      return advisories
    }

    for (const affected of vuln.affected) {
      // Only check packages that match by name (Issue 1 optimization)
      const matchingPackages = packagesByName.get(affected.package.name)
      if (!matchingPackages) {
        continue
      }

      for (const pkg of matchingPackages) {
        const pairKey = `${vuln.id}:${pkg.name}@${pkg.version}`

        // Avoid duplicate advisories for same vulnerability+package
        if (processedPairs.has(pairKey)) {
          continue
        }

        if (isPackageAffected(pkg, affected)) {
          // Check if this vulnerability should be ignored
          const ignoreResult = shouldIgnoreVulnerability(
            vuln.id,
            vuln.aliases,
            pkg.name,
            compiledConfig,
          )

          if (ignoreResult.ignored) {
            logger.debug(`Ignoring ${vuln.id} for ${pkg.name}: ${ignoreResult.reason}`)
            ignoredCount++
            processedPairs.add(pairKey)
            continue
          }

          const advisory = createAdvisory(vuln, pkg)
          advisories.push(advisory)
          processedPairs.add(pairKey)

          logger.debug(`Created advisory for ${pkg.name}@${pkg.version}`, {
            vulnerability: vuln.id,
            level: advisory.level,
          })

          // Only create one advisory per package per vulnerability
          break
        }
      }
    }

    return advisories
  }

  /**
   * Convert OSV vulnerabilities to Bun security advisories
   * Matches vulnerabilities against input packages and generates appropriate advisories
   */
  function processVulnerabilities(
    vulnerabilities: OSVVulnerability[],
    packages: Bun.Security.Package[],
  ): Bun.Security.Advisory[] {
    if (vulnerabilities.length === 0 || packages.length === 0) {
      return []
    }

    logger.info(
      `Processing ${vulnerabilities.length} vulnerabilities against ${packages.length} packages`,
    )

    // Build package index for O(1) lookup by name (Issue 1 optimization)
    const packagesByName = new Map<string, Bun.Security.Package[]>()
    for (const pkg of packages) {
      const existing = packagesByName.get(pkg.name)
      if (existing) {
        existing.push(pkg)
      } else {
        packagesByName.set(pkg.name, [pkg])
      }
    }

    const advisories: Bun.Security.Advisory[] = []
    const processedPairs = new Set<string>() // Track processed vuln+package pairs
    ignoredCount = 0

    for (const vuln of vulnerabilities) {
      const vulnAdvisories = processVulnerability(
        vuln,
        packagesByName,
        processedPairs,
        compiledIgnoreConfig,
      )
      advisories.push(...vulnAdvisories)
    }

    if (ignoredCount > 0) {
      logger.info(`Ignored ${ignoredCount} vulnerabilities based on config`)
    }

    logger.info(`Generated ${advisories.length} security advisories`)
    return advisories
  }

  return {
    processVulnerabilities,
  }
}
