import type { FatalSeverity } from "@repo/core"
import { SECURITY, logger } from "@repo/core"

import type { OSVVulnerability } from "./schema.js"

/**
 * Map OSV vulnerability data to Bun security advisory level
 * Uses multiple data sources: database_specific.severity, CVSS scores, etc.
 */
export function mapSeverityToLevel(vuln: OSVVulnerability): "fatal" | "warn" {
  // Check database_specific.severity first (most authoritative)
  const dbSeverity = vuln.database_specific?.severity
  if (dbSeverity && isFatalSeverity(dbSeverity)) {
    logger.debug(`Vulnerability ${vuln.id} marked fatal due to database severity: ${dbSeverity}`)
    return "fatal"
  }

  // Check CVSS scores if available
  if (vuln.severity) {
    const cvssScore = extractHighestCVSSScore(vuln.severity)
    if (cvssScore !== null && cvssScore >= SECURITY.CVSS_FATAL_THRESHOLD) {
      logger.debug(`Vulnerability ${vuln.id} marked fatal due to CVSS score: ${cvssScore}`)
      return "fatal"
    }
  }

  // Default to warning level for all other cases
  logger.debug(`Vulnerability ${vuln.id} marked as warning (default)`)
  return "warn"
}

/**
 * Check if a severity string represents a fatal level
 */
function isFatalSeverity(severity: unknown): severity is FatalSeverity {
  return (
    typeof severity === "string" && SECURITY.FATAL_SEVERITIES.includes(severity as FatalSeverity)
  )
}

/**
 * Extract the highest CVSS score from severity array
 * Supports CVSS v2, v3.0, and v3.1 formats
 */
function extractHighestCVSSScore(severities: OSVVulnerability["severity"]): number | null {
  if (!Array.isArray(severities)) return null

  let highestScore: number | null = null

  for (const severity of severities) {
    if (!severity.type.startsWith("CVSS")) continue

    const score = parseCVSSScore(severity.score, severity.type)
    if (score !== null && (highestScore === null || score > highestScore)) {
      highestScore = score
    }
  }

  return highestScore
}

/**
 * Parse CVSS score from various formats
 * Handles CVSS:3.1/..., numeric scores, and other formats
 */
function parseCVSSScore(scoreString: string, type: string): number | null {
  try {
    // Handle CVSS vector strings like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/10.0"
    if (scoreString.includes("CVSS:")) {
      const vectorMatch = scoreString.match(/CVSS:[\d.]+\/.*?(\d+\.\d+|\d+)$/)
      if (vectorMatch?.[1]) {
        return parseFloat(vectorMatch[1])
      }

      // Some CVSS strings have the score embedded differently
      const scoreMatch = scoreString.match(/(\d+\.\d+|\d+)$/)
      if (scoreMatch?.[1]) {
        return parseFloat(scoreMatch[1])
      }
    }

    // Handle plain numeric scores
    const numericScore = parseFloat(scoreString)
    if (!Number.isNaN(numericScore) && numericScore >= 0 && numericScore <= 10) {
      return numericScore
    }

    logger.debug(`Failed to parse CVSS score`, { type, scoreString })
    return null
  } catch (error) {
    logger.warn(`Error parsing CVSS score`, {
      type,
      scoreString,
      error: error instanceof Error ? error.message : String(error),
    })
    return null
  }
}
