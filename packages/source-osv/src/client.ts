import type { OSVQuery, OSVVulnerability } from "./schema.js"
import { OSVResponseSchema, OSVBatchResponseSchema, OSVVulnerabilitySchema } from "./schema.js"
import type { OsvConfig } from "@repo/core"
import { OSV_API, HTTP, PERFORMANCE, CONFIG_DEFAULTS, withRetry, logger } from "@repo/core"

/** OSV Client interface */
export interface OSVClient {
  queryVulnerabilities(packages: Bun.Security.Package[]): Promise<OSVVulnerability[]>
}

/** Options for creating OSV client */
export interface CreateOSVClientOptions {
  osv?: OsvConfig
}

/**
 * Create an OSV API Client
 * Handles all communication with OSV.dev API including batch queries and individual lookups
 */
export function createOSVClient(options: CreateOSVClientOptions = {}): OSVClient {
  const osvConfig = options.osv ?? CONFIG_DEFAULTS.osv
  const baseUrl = osvConfig.apiBaseUrl ?? OSV_API.BASE_URL
  const timeout = osvConfig.timeoutMs ?? OSV_API.TIMEOUT_MS
  const useBatch = !(osvConfig.disableBatch ?? false)

  /**
   * Deduplicate packages by name@version to avoid redundant queries
   */
  function deduplicatePackages(packages: Bun.Security.Package[]): Bun.Security.Package[] {
    const packageMap = new Map<string, Bun.Security.Package>()

    for (const pkg of packages) {
      const key = `${pkg.name}@${pkg.version}`
      if (!packageMap.has(key)) {
        packageMap.set(key, pkg)
      }
    }

    const uniquePackages = Array.from(packageMap.values())

    if (uniquePackages.length < packages.length) {
      logger.debug(
        `Deduplicated ${packages.length} packages to ${uniquePackages.length} unique packages`,
      )
    }

    return uniquePackages
  }

  /**
   * Execute a single batch query
   */
  async function executeBatchQuery(queries: OSVQuery[]): Promise<string[]> {
    const vulnerabilityIds: string[] = []

    const response = await withRetry(async () => {
      const res = await fetch(`${baseUrl}/querybatch`, {
        method: "POST",
        headers: {
          "Content-Type": HTTP.CONTENT_TYPE,
          "User-Agent": HTTP.USER_AGENT,
        },
        body: JSON.stringify({ queries }),
        signal: AbortSignal.timeout(timeout),
      })

      if (!res.ok) {
        throw new Error(`OSV API returned ${res.status}: ${res.statusText}`)
      }

      return res
    }, `OSV batch query (${queries.length} packages)`)

    const data = await response.json()
    const parsed = OSVBatchResponseSchema.parse(data)

    // Extract vulnerability IDs from batch response
    for (const result of parsed.results) {
      if (result.vulns) {
        vulnerabilityIds.push(...result.vulns.map((v) => v.id))
      }
    }

    const vulnCount = parsed.results.reduce((sum, r) => sum + (r.vulns?.length || 0), 0)
    logger.debug(`Batch query found ${vulnCount} vulnerabilities across ${queries.length} packages`)

    return [...new Set(vulnerabilityIds)] // Deduplicate IDs
  }

  /**
   * Fetch a single vulnerability by ID
   */
  async function fetchSingleVulnerability(id: string): Promise<OSVVulnerability | null> {
    try {
      return await withRetry(async () => {
        const response = await fetch(`${baseUrl}/vulns/${id}`, {
          headers: {
            "User-Agent": HTTP.USER_AGENT,
          },
          signal: AbortSignal.timeout(timeout),
        })

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`)
        }

        const data = await response.json()
        return OSVVulnerabilitySchema.parse(data)
      }, `Get vulnerability ${id}`)
    } catch (error) {
      logger.warn(`Failed to fetch vulnerability ${id}`, {
        error: error instanceof Error ? error.message : String(error),
      })
      return null
    }
  }

  /**
   * Fetch detailed vulnerability information by IDs
   */
  async function fetchVulnerabilityDetails(ids: string[]): Promise<OSVVulnerability[]> {
    if (ids.length === 0) return []

    const uniqueIds = [...new Set(ids)] // Deduplicate requests
    logger.debug(`Fetching details for ${uniqueIds.length} vulnerabilities`)

    // Process in smaller chunks to avoid overwhelming the API
    const chunkSize = PERFORMANCE.MAX_CONCURRENT_DETAILS
    const vulnerabilities: OSVVulnerability[] = []

    for (let i = 0; i < uniqueIds.length; i += chunkSize) {
      const chunk = uniqueIds.slice(i, i + chunkSize)
      const chunkResults = await Promise.allSettled(chunk.map((id) => fetchSingleVulnerability(id)))

      for (const result of chunkResults) {
        if (result.status === "fulfilled" && result.value) {
          vulnerabilities.push(result.value)
        }
      }
    }

    logger.debug(`Retrieved ${vulnerabilities.length}/${uniqueIds.length} vulnerability details`)
    return vulnerabilities
  }

  /**
   * Use batch API for efficient querying
   * Follows OSV.dev recommended pattern: batch query -> individual details
   */
  async function queryWithBatch(queries: OSVQuery[]): Promise<OSVVulnerability[]> {
    const vulnerabilityIds: string[] = []

    // Process queries in batches
    for (let i = 0; i < queries.length; i += OSV_API.MAX_BATCH_SIZE) {
      const batchQueries = queries.slice(i, i + OSV_API.MAX_BATCH_SIZE)

      try {
        const batchIds = await executeBatchQuery(batchQueries)
        vulnerabilityIds.push(...batchIds)
      } catch (error) {
        logger.error(`Batch query failed for ${batchQueries.length} packages`, {
          error: error instanceof Error ? error.message : String(error),
          startIndex: i,
        })
        // Continue with next batch rather than failing completely
      }
    }

    // Fetch detailed vulnerability information
    return await fetchVulnerabilityDetails(vulnerabilityIds)
  }

  /**
   * Query a single package with pagination support
   */
  async function querySinglePackage(query: OSVQuery): Promise<OSVVulnerability[]> {
    const allVulns: OSVVulnerability[] = []
    let currentQuery = { ...query }

    while (true) {
      try {
        const response = await withRetry(
          async () => {
            const res = await fetch(`${baseUrl}/query`, {
              method: "POST",
              headers: {
                "Content-Type": HTTP.CONTENT_TYPE,
                "User-Agent": HTTP.USER_AGENT,
              },
              body: JSON.stringify(currentQuery),
              signal: AbortSignal.timeout(timeout),
            })

            if (!res.ok) {
              throw new Error(`HTTP ${res.status}: ${res.statusText}`)
            }

            return res
          },
          `OSV query for ${query.package?.name || "unknown"}@${query.version || "unknown"}`,
        )

        const data = await response.json()
        const parsed = OSVResponseSchema.parse(data)

        // Add vulnerabilities from this page
        if (parsed.vulns) {
          allVulns.push(...parsed.vulns)
        }

        // Check for pagination
        if (parsed.next_page_token) {
          currentQuery = { ...query, page_token: parsed.next_page_token }
        } else {
          break // No more pages
        }
      } catch (error) {
        logger.warn(
          `Query failed for ${query.package?.name || "unknown"}@${query.version || "unknown"}`,
          {
            error: error instanceof Error ? error.message : String(error),
          },
        )
        break // Exit pagination loop on error
      }
    }

    return allVulns
  }

  /**
   * Query packages individually (fallback method)
   */
  async function queryIndividually(queries: OSVQuery[]): Promise<OSVVulnerability[]> {
    const responses = await Promise.allSettled(queries.map((query) => querySinglePackage(query)))

    const vulnerabilities: OSVVulnerability[] = []
    let successCount = 0

    for (const response of responses) {
      if (response.status === "fulfilled") {
        vulnerabilities.push(...response.value)
        successCount++
      }
    }

    logger.debug(`Individual queries completed: ${successCount}/${queries.length} successful`)
    return vulnerabilities
  }

  /**
   * Query vulnerabilities for multiple packages
   * Uses batch API when possible for better performance
   */
  async function queryVulnerabilities(
    packages: Bun.Security.Package[],
  ): Promise<OSVVulnerability[]> {
    if (packages.length === 0) {
      return []
    }

    // Deduplicate packages by name@version
    const uniquePackages = deduplicatePackages(packages)
    logger.debug(`Scanning ${uniquePackages.length} unique packages (${packages.length} total)`)

    // Create OSV queries
    const queries = uniquePackages.map((pkg) => ({
      package: {
        name: pkg.name,
        ecosystem: OSV_API.DEFAULT_ECOSYSTEM,
      },
      version: pkg.version,
    }))

    if (useBatch && queries.length > 1) {
      return await queryWithBatch(queries)
    } else {
      return await queryIndividually(queries)
    }
  }

  return {
    queryVulnerabilities,
  }
}
