/**
 * Process npm advisories into Bun security advisories
 */

import type { NpmAdvisory } from "./schema.js"
import type { IgnoreConfig, CompiledIgnoreConfig } from "../../config.js"
import { compileIgnoreConfig, shouldIgnoreVulnerability } from "../../config.js"
import { mapSeverityToLevel } from "./severity.js"
import { SECURITY } from "./constants.js"
import { logger } from "../../logger.js"

/**
 * Process npm advisories into Bun security advisories
 * Handles advisory-to-package matching and Bun advisory generation
 */
export class AdvisoryProcessor {
  private readonly compiledIgnoreConfig: CompiledIgnoreConfig
  private ignoredCount = 0

  constructor(ignoreConfig: IgnoreConfig = {}) {
    this.compiledIgnoreConfig = compileIgnoreConfig(ignoreConfig)
  }

  /**
   * Convert npm advisories to Bun security advisories
   * Matches advisories against input packages and generates appropriate advisories
   */
  processAdvisories(
    advisories: NpmAdvisory[],
    packages: Bun.Security.Package[],
  ): Bun.Security.Advisory[] {
    if (advisories.length === 0 || packages.length === 0) {
      return []
    }

    logger.info(`Processing ${advisories.length} advisories against ${packages.length} packages`)

    // Reset ignored count for this batch
    this.ignoredCount = 0

    const bunAdvisories: Bun.Security.Advisory[] = []
    const processedPairs = new Set<string>() // Track processed advisory+package pairs

    for (const advisory of advisories) {
      const matched = this.processAdvisory(advisory, packages, processedPairs)
      bunAdvisories.push(...matched)
    }

    if (this.ignoredCount > 0) {
      logger.info(`Ignored ${this.ignoredCount} advisories based on configuration`)
    }
    logger.info(`Generated ${bunAdvisories.length} security advisories`)
    return bunAdvisories
  }

  /**
   * Build aliases from CVEs and GHSA ID for deduplication
   */
  private buildAliases(advisory: NpmAdvisory): string[] {
    const aliases = new Set<string>([
      ...(advisory.cves ?? []),
      ...(advisory.github_advisory_id ? [advisory.github_advisory_id] : []),
    ])

    const ghsaFromUrl = this.extractGhsaFromUrl(advisory.url)
    if (ghsaFromUrl) {
      aliases.add(ghsaFromUrl)
    }

    return Array.from(aliases)
  }

  private extractGhsaFromUrl(url: string): string | null {
    const match = url.match(/GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}/i)
    return match ? match[0] : null
  }

  /**
   * Process a single npm advisory against all packages
   */
  private processAdvisory(
    advisory: NpmAdvisory,
    packages: Bun.Security.Package[],
    processedPairs: Set<string>,
  ): Bun.Security.Advisory[] {
    const bunAdvisories: Bun.Security.Advisory[] = []

    // Get package name from advisory (prefer 'name' over deprecated 'module_name')
    const advisoryPackageName = advisory.name || advisory.module_name
    if (!advisoryPackageName) {
      logger.debug(`Advisory ${advisory.id} has no package name`)
      return bunAdvisories
    }

    // Build aliases for ignore check and deduplication
    const aliases = this.buildAliases(advisory)

    // Find matching packages
    for (const pkg of packages) {
      // Check if package name matches
      if (pkg.name !== advisoryPackageName) {
        continue
      }

      const pairKey = `${advisory.id}:${pkg.name}@${pkg.version}`

      // Avoid duplicate advisories for same advisory+package
      if (processedPairs.has(pairKey)) {
        continue
      }

      // Check if package version is affected
      if (this.isVersionAffected(pkg.version, advisory.vulnerable_versions)) {
        // Check ignore configuration before creating advisory
        const ignoreResult = shouldIgnoreVulnerability(
          String(advisory.id),
          aliases,
          pkg.name,
          this.compiledIgnoreConfig,
        )

        if (ignoreResult.ignored) {
          logger.debug(`Ignoring ${advisory.id} for ${pkg.name}: ${ignoreResult.reason}`)
          this.ignoredCount++
          processedPairs.add(pairKey)
          continue
        }

        const bunAdvisory = this.createBunAdvisory(advisory, pkg, aliases)
        bunAdvisories.push(bunAdvisory)
        processedPairs.add(pairKey)

        logger.debug(`Created advisory for ${pkg.name}@${pkg.version}`, {
          advisory: advisory.id,
          level: bunAdvisory.level,
        })
      }
    }

    return bunAdvisories
  }

  /**
   * Check if a package version is affected by the vulnerable version range
   * Uses Bun's built-in semver.satisfies for version matching
   */
  private isVersionAffected(version: string, vulnerableVersions: string): boolean {
    try {
      // npm vulnerable_versions is a semver range like ">=1.0.0 <2.0.0"
      return Bun.semver.satisfies(version, vulnerableVersions)
    } catch (error) {
      logger.warn(`Failed to parse version range "${vulnerableVersions}" for version ${version}`, {
        error: error instanceof Error ? error.message : String(error),
      })
      return false
    }
  }

  /**
   * Create a Bun security advisory from an npm advisory and affected package
   */
  private createBunAdvisory(
    advisory: NpmAdvisory,
    pkg: Bun.Security.Package,
    aliases: string[],
  ): Bun.Security.Advisory {
    const level = mapSeverityToLevel(advisory.severity)
    const description = this.getAdvisoryDescription(advisory)
    const message = advisory.title || `Security advisory ${advisory.id}`

    return {
      id: String(advisory.id),
      message,
      level,
      package: pkg.name,
      url: advisory.url,
      description,
      aliases,
    }
  }

  /**
   * Get a descriptive summary of the advisory
   * Uses overview, recommendation, or truncates if too long
   */
  private getAdvisoryDescription(advisory: NpmAdvisory): string | null {
    // Prefer overview
    if (advisory.overview?.trim()) {
      const overview = advisory.overview.trim()
      if (overview.length <= SECURITY.MAX_DESCRIPTION_LENGTH) {
        return overview
      }
      // Truncate long overview to first sentence or max length
      const firstSentence = overview.match(/^[^.!?]*[.!?]/)?.[0]
      if (firstSentence && firstSentence.length <= SECURITY.MAX_DESCRIPTION_LENGTH) {
        return firstSentence
      }
      return `${overview.substring(0, SECURITY.MAX_DESCRIPTION_LENGTH - 3)}...`
    }

    // Fall back to recommendation
    if (advisory.recommendation?.trim()) {
      const recommendation = advisory.recommendation.trim()
      if (recommendation.length <= SECURITY.MAX_DESCRIPTION_LENGTH) {
        return recommendation
      }
      return `${recommendation.substring(0, SECURITY.MAX_DESCRIPTION_LENGTH - 3)}...`
    }

    // No description available
    return null
  }
}
