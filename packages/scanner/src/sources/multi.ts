import type { VulnerabilitySource } from "@repo/core"
import { logger } from "@repo/core"

/** Multi-source scanner interface */
export interface MultiSourceScanner {
  scan(packages: Bun.Security.Package[]): Promise<Bun.Security.Advisory[]>
}

/**
 * Create a scanner that queries multiple vulnerability sources in parallel
 * Deduplicates results by ID/alias and takes highest severity for duplicates
 */
export function createMultiSourceScanner(sources: VulnerabilitySource[]): MultiSourceScanner {
  if (sources.length === 0) {
    throw new Error("MultiSourceScanner requires at least one source")
  }

  /**
   * Compare severity levels - returns true if a is higher severity than b
   */
  function isHigherSeverity(
    a: Bun.Security.Advisory["level"],
    b: Bun.Security.Advisory["level"],
  ): boolean {
    const priority: Record<string, number> = { fatal: 2, warn: 1 }
    return (priority[a] ?? 0) > (priority[b] ?? 0)
  }

  /**
   * Deduplicate advisories by package + any overlapping id/alias
   * When duplicates exist, keep the one with highest severity (fatal > warn)
   */
  function deduplicateAdvisories(advisories: Bun.Security.Advisory[]): Bun.Security.Advisory[] {
    // Map from key -> advisory, where key is "package:id" for any id/alias
    const map = new Map<string, Bun.Security.Advisory>()

    for (const advisory of advisories) {
      const currentIds = new Set([advisory.id, ...(advisory.aliases ?? [])])
      const packageKey = advisory.package

      // Find if any existing entry shares an id/alias with this advisory
      let existingKey: string | null = null
      for (const id of currentIds) {
        const key = `${packageKey}:${id}`
        if (map.has(key)) {
          existingKey = key
          break
        }
      }

      if (!existingKey) {
        // No existing entry - add all id/alias keys pointing to this advisory
        for (const id of currentIds) {
          map.set(`${packageKey}:${id}`, advisory)
        }
        continue
      }

      // Existing entry found - keep the one with higher severity
      const existing = map.get(existingKey)!
      const winner = isHigherSeverity(advisory.level, existing.level) ? advisory : existing

      // Merge all IDs from both advisories and update all keys to point to winner
      const existingIds = new Set([existing.id, ...(existing.aliases ?? [])])
      const mergedIds = new Set([...currentIds, ...existingIds])

      for (const id of mergedIds) {
        map.set(`${packageKey}:${id}`, winner)
      }
    }

    // De-dupe map values (multiple keys point at same object)
    return Array.from(new Set(map.values()))
  }

  async function scan(packages: Bun.Security.Package[]): Promise<Bun.Security.Advisory[]> {
    const sourceNames = sources.map((s) => s.name).join(", ")
    logger.info(`Scanning with sources: ${sourceNames}`)

    // Query all sources in parallel
    const results = await Promise.allSettled(sources.map((source) => source.scan(packages)))

    // Collect all advisories
    const allAdvisories: Bun.Security.Advisory[] = []

    for (const [i, result] of results.entries()) {
      const source = sources[i]
      if (!source) continue

      if (result.status === "fulfilled") {
        logger.debug(`[${source.name}] Found ${result.value.length} advisories`)
        allAdvisories.push(...result.value)
      } else {
        logger.error(`[${source.name}] Scan failed`, {
          error: result.reason instanceof Error ? result.reason.message : String(result.reason),
        })
      }
    }

    return deduplicateAdvisories(allAdvisories)
  }

  return {
    scan,
  }
}
