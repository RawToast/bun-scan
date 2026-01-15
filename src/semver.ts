/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

import type { OSVAffected } from "./schema.js"
import { logger } from "./logger.js"

/**
 * Check if a package version is affected by an OSV vulnerability
 * Handles complex OSV range formats including introduced/fixed/last_affected events
 */
export function isPackageAffected(pkg: Bun.Security.Package, affected: OSVAffected): boolean {
  // Package name must match
  if (affected.package.name !== pkg.name) {
    return false
  }

  // Check explicit versions list first (fastest path)
  if (affected.versions?.includes(pkg.version)) {
    logger.debug(`Package ${pkg.name}@${pkg.version} found in explicit versions list`)
    return true
  }

  // Check version ranges
  if (affected.ranges) {
    for (const range of affected.ranges) {
      if (isVersionInRange(pkg.version, range)) {
        return true
      }
    }
  }

  return false
}

/**
 * Check if a version falls within an OSV range
 * Supports SEMVER and other range types
 */
function isVersionInRange(version: string, range: NonNullable<OSVAffected["ranges"]>[0]): boolean {
  if (!range.events || range.events.length === 0) {
    return false
  }

  if (range.type === "SEMVER") {
    return isVersionInSemverRange(version, range)
  }

  // For non-SEMVER ranges (GIT, ECOSYSTEM), we can't reliably compare
  logger.debug(`Unsupported range type: ${range.type}`, { range })
  return false
}

/**
 * Check if version satisfies SEMVER range events
 * Handles OSV's introduced/fixed/last_affected event model
 */
function isVersionInSemverRange(
  version: string,
  range: {
    events: Array<{
      introduced?: string
      fixed?: string
      last_affected?: string
    }>
  },
): boolean {
  try {
    // Build semver range string from OSV events
    const rangeExpressions: string[] = []

    for (const event of range.events) {
      if (event.introduced) {
        if (event.introduced === "0") {
          rangeExpressions.push("*")
        } else {
          rangeExpressions.push(`>=${event.introduced}`)
        }
      }

      if (event.fixed) {
        rangeExpressions.push(`<${event.fixed}`)
      }

      if (event.last_affected) {
        rangeExpressions.push(`<=${event.last_affected}`)
      }
    }

    if (rangeExpressions.length === 0) {
      return false
    }

    // Combine range expressions with AND logic
    const combinedRange = rangeExpressions.join(" ")

    logger.debug(`Checking ${version} against range: ${combinedRange}`)

    return Bun.semver.satisfies(version, combinedRange)
  } catch (error) {
    logger.warn(`Failed to parse semver range`, {
      version,
      range: range.events,
      error: error instanceof Error ? error.message : String(error),
    })
    return false
  }
}
