/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

import type { OSVVulnerability } from "./schema.js"
import { isPackageAffected } from "./semver.js"
import { mapSeverityToLevel } from "./severity.js"
import { SECURITY } from "./constants.js"
import { logger } from "./logger.js"
import { type IgnoreConfig, shouldIgnoreVulnerability } from "./config.js"

/**
 * Process OSV vulnerabilities into Bun security advisories
 * Handles vulnerability-to-package matching and advisory generation
 */
export class VulnerabilityProcessor {
  private ignoreConfig: IgnoreConfig
  private ignoredCount = 0

  constructor(ignoreConfig: IgnoreConfig = {}) {
    this.ignoreConfig = ignoreConfig
  }

  /**
   * Convert OSV vulnerabilities to Bun security advisories
   * Matches vulnerabilities against input packages and generates appropriate advisories
   */
  processVulnerabilities(
    vulnerabilities: OSVVulnerability[],
    packages: Bun.Security.Package[],
  ): Bun.Security.Advisory[] {
    if (vulnerabilities.length === 0 || packages.length === 0) {
      return []
    }

    logger.info(
      `Processing ${vulnerabilities.length} vulnerabilities against ${packages.length} packages`,
    )

    const advisories: Bun.Security.Advisory[] = []
    const processedPairs = new Set<string>() // Track processed vuln+package pairs
    this.ignoredCount = 0

    for (const vuln of vulnerabilities) {
      const vulnAdvisories = this.processVulnerability(vuln, packages, processedPairs)
      advisories.push(...vulnAdvisories)
    }

    if (this.ignoredCount > 0) {
      logger.info(`Ignored ${this.ignoredCount} vulnerabilities based on config`)
    }

    logger.info(`Generated ${advisories.length} security advisories`)
    return advisories
  }

  /**
   * Process a single vulnerability against all packages
   */
  private processVulnerability(
    vuln: OSVVulnerability,
    packages: Bun.Security.Package[],
    processedPairs: Set<string>,
  ): Bun.Security.Advisory[] {
    const advisories: Bun.Security.Advisory[] = []

    if (!vuln.affected) {
      logger.debug(`Vulnerability ${vuln.id} has no affected packages`)
      return advisories
    }

    for (const affected of vuln.affected) {
      for (const pkg of packages) {
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
            this.ignoreConfig,
          )

          if (ignoreResult.ignored) {
            logger.debug(`Ignoring ${vuln.id} for ${pkg.name}: ${ignoreResult.reason}`)
            this.ignoredCount++
            processedPairs.add(pairKey)
            continue
          }

          const advisory = this.createAdvisory(vuln, pkg)
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
   * Create a Bun security advisory from an OSV vulnerability and affected package
   */
  private createAdvisory(vuln: OSVVulnerability, pkg: Bun.Security.Package): Bun.Security.Advisory {
    const level = mapSeverityToLevel(vuln)
    const url = this.getVulnerabilityUrl(vuln)
    const description = this.getVulnerabilityDescription(vuln)

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
   * Get the best URL to reference for this vulnerability
   * Prioritizes official references and known vulnerability databases
   */
  private getVulnerabilityUrl(vuln: OSVVulnerability): string | null {
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

    // Then CVE URLs
    const cveRef = vuln.references.find((ref) => {
      try {
        const url = new URL(ref.url)
        return url.hostname === "cve.mitre.org" || url.hostname === "nvd.nist.gov"
      } catch {
        return false
      }
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
  private getVulnerabilityDescription(vuln: OSVVulnerability): string | null {
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
}
