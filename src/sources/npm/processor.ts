/**
 * Process npm advisories into Bun security advisories
 */

import type { NpmAdvisory } from "./schema.js"
import type { IgnoreConfig } from "../../config.js"
import { mapSeverityToLevel } from "./severity.js"
import { SECURITY } from "./constants.js"
import { logger } from "../../logger.js"

/**
 * Process npm advisories into Bun security advisories
 * Handles advisory-to-package matching and Bun advisory generation
 */
export class AdvisoryProcessor {
  constructor(_ignoreConfig: IgnoreConfig) {
    // ignoreConfig reserved for future filtering implementation
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

    const bunAdvisories: Bun.Security.Advisory[] = []
    const processedPairs = new Set<string>() // Track processed advisory+package pairs

    for (const advisory of advisories) {
      const matched = this.processAdvisory(advisory, packages, processedPairs)
      bunAdvisories.push(...matched)
    }

    logger.info(`Generated ${bunAdvisories.length} security advisories`)
    return bunAdvisories
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
        const bunAdvisory = this.createBunAdvisory(advisory, pkg)
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
