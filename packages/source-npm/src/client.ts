/**
 * npm Audit API Client
 * Handles communication with npm registry's bulk advisory endpoint
 */

import type { NpmAdvisory, NpmAuditRequest } from "./schema.js"
import { NpmAuditResponseSchema } from "./schema.js"
import { NPM_AUDIT_API, HTTP, getConfig, ENV } from "./constants.js"
import { withRetry, logger } from "@repo/core"

/** npm Audit Client interface */
export interface NpmAuditClient {
  queryVulnerabilities(packages: Bun.Security.Package[]): Promise<NpmAdvisory[]>
}

/**
 * Create an npm Audit API Client
 * Handles communication with npm registry's bulk advisory endpoint
 */
export function createNpmAuditClient(): NpmAuditClient {
  const registryUrl = getConfig(ENV.REGISTRY_URL, NPM_AUDIT_API.REGISTRY_URL)
  const timeout = getConfig(ENV.TIMEOUT_MS, NPM_AUDIT_API.TIMEOUT_MS)

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
   * Build npm audit request payload
   * Groups packages by name and collects their versions
   */
  function buildRequestPayload(packages: Bun.Security.Package[]): NpmAuditRequest {
    const payload: NpmAuditRequest = {}

    for (const pkg of packages) {
      if (!payload[pkg.name]) {
        payload[pkg.name] = []
      }
      const versions = payload[pkg.name]
      if (versions && !versions.includes(pkg.version)) {
        versions.push(pkg.version)
      }
    }

    return payload
  }

  /**
   * Execute bulk advisory query with gzip compression
   */
  async function executeBulkQuery(payload: NpmAuditRequest): Promise<NpmAdvisory[]> {
    const packageCount = Object.keys(payload).length
    const versionCount = Object.values(payload).reduce((sum, versions) => sum + versions.length, 0)

    logger.debug(`Querying ${packageCount} packages with ${versionCount} versions`)

    // Compress payload with gzip
    const jsonPayload = JSON.stringify(payload)
    const compressedPayload = Bun.gzipSync(jsonPayload)

    const response = await withRetry(
      async () => {
        const url = `${registryUrl}${NPM_AUDIT_API.BULK_ADVISORY_PATH}`
        const res = await fetch(url, {
          method: "POST",
          headers: {
            "Content-Type": HTTP.CONTENT_TYPE,
            "Content-Encoding": HTTP.CONTENT_ENCODING,
            "User-Agent": HTTP.USER_AGENT,
            Accept: HTTP.CONTENT_TYPE,
          },
          body: compressedPayload,
          signal: AbortSignal.timeout(timeout),
        })

        if (!res.ok) {
          throw new Error(`npm registry returned ${res.status}: ${res.statusText}`)
        }

        return res
      },
      `npm audit query (${packageCount} packages)`,
      {
        maxAttempts: NPM_AUDIT_API.MAX_RETRY_ATTEMPTS + 1,
        delayMs: NPM_AUDIT_API.RETRY_DELAY_MS,
      },
    )

    const data = await response.json()

    // Parse response: package name -> advisory array
    const parsedResponse = NpmAuditResponseSchema.parse(data)

    // Flatten all advisory arrays into a single list
    const advisories: NpmAdvisory[] = []
    for (const [packageName, packageAdvisories] of Object.entries(parsedResponse)) {
      // Attach package name to each advisory for matching
      for (const advisory of packageAdvisories) {
        advisories.push({
          ...advisory,
          name: advisory.name || packageName,
        })
      }
    }

    logger.info(`Found ${advisories.length} advisories for ${packageCount} packages`)

    return advisories
  }

  /**
   * Query packages in batches when count exceeds max
   */
  async function queryInBatches(packages: Bun.Security.Package[]): Promise<NpmAdvisory[]> {
    const advisories: NpmAdvisory[] = []
    const batchSize = NPM_AUDIT_API.MAX_PACKAGES_PER_REQUEST

    for (let i = 0; i < packages.length; i += batchSize) {
      const batch = packages.slice(i, i + batchSize)
      const payload = buildRequestPayload(batch)

      try {
        const batchAdvisories = await executeBulkQuery(payload)
        advisories.push(...batchAdvisories)
      } catch (error) {
        logger.error(`Batch query failed for ${batch.length} packages`, {
          error: error instanceof Error ? error.message : String(error),
          startIndex: i,
        })
        // Continue with next batch rather than failing completely
      }
    }

    return advisories
  }

  /**
   * Query vulnerabilities for multiple packages
   * Uses npm's bulk advisory endpoint
   */
  async function queryVulnerabilities(packages: Bun.Security.Package[]): Promise<NpmAdvisory[]> {
    if (packages.length === 0) {
      return []
    }

    // Deduplicate packages by name@version
    const uniquePackages = deduplicatePackages(packages)
    logger.info(`Scanning ${uniquePackages.length} unique packages (${packages.length} total)`)

    // Build request payload: { "package-name": ["version1", "version2"] }
    const requestPayload = buildRequestPayload(uniquePackages)

    // Process in batches if needed
    if (uniquePackages.length > NPM_AUDIT_API.MAX_PACKAGES_PER_REQUEST) {
      return await queryInBatches(uniquePackages)
    }

    return await executeBulkQuery(requestPayload)
  }

  return {
    queryVulnerabilities,
  }
}
