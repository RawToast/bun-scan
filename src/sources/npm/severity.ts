/**
 * npm severity mapping utilities
 */

import type { NpmSeverity, FatalSeverity } from "./types.js"
import { SECURITY } from "./constants.js"
import { logger } from "../../logger.js"

/**
 * Map npm audit severity to Bun security advisory level
 * npm uses: critical, high, moderate, low, info
 */
export function mapSeverityToLevel(severity: NpmSeverity): "fatal" | "warn" {
  // Check if severity is fatal level
  if (isFatalSeverity(severity)) {
    logger.debug(`Advisory marked fatal due to npm severity: ${severity}`)
    return "fatal"
  }

  // All other severities (moderate, low, info) map to warning
  logger.debug(`Advisory marked as warning (severity: ${severity})`)
  return "warn"
}

/**
 * Check if a severity string represents a fatal level
 * Fatal levels: critical, high
 */
function isFatalSeverity(severity: NpmSeverity): severity is FatalSeverity {
  return SECURITY.FATAL_SEVERITIES.includes(severity as FatalSeverity)
}

/**
 * Map npm severity to numeric priority for sorting
 * Higher numbers = more severe
 */
export function severityToPriority(severity: NpmSeverity): number {
  const priorityMap: Record<NpmSeverity, number> = {
    critical: 5,
    high: 4,
    moderate: 3,
    low: 2,
    info: 1,
  }

  return priorityMap[severity] ?? 0
}

/**
 * Check if a CVSS score qualifies as fatal
 * CVSS scores range from 0-10
 */
export function isCvssScoreFatal(score: number): boolean {
  return score >= SECURITY.CVSS_FATAL_THRESHOLD
}
