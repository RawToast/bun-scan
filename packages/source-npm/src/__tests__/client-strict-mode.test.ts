import { beforeEach, afterEach, describe, expect, test } from "bun:test"
import { createNpmAuditClient } from "../client.js"

describe("NpmAuditClient strict mode behavior", () => {
  const makePackage = (name: string, version: string): Bun.Security.Package => ({
    name,
    version,
    tarball: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
    requestedRange: "*",
  })

  let originalLogLevel: string | undefined

  beforeEach(() => {
    originalLogLevel = Bun.env.BUN_SCAN_LOG_LEVEL
    Bun.env.BUN_SCAN_LOG_LEVEL = "error"
  })

  afterEach(() => {
    if (originalLogLevel === undefined) {
      delete Bun.env.BUN_SCAN_LOG_LEVEL
    } else {
      Bun.env.BUN_SCAN_LOG_LEVEL = originalLogLevel
    }
  })

  test("rethrows on batch query failure when failOnScannerError is true", async () => {
    const client = createNpmAuditClient({
      failOnScannerError: true,
    })

    // Mock fetch to throw for bulk advisory queries
    const originalFetch = globalThis.fetch
    const mockFetch = async (url: string | Request | URL, options?: RequestInit) => {
      const urlStr = url.toString()
      if (urlStr.includes("-/npm/v1/security/advisories/bulk")) {
        throw new Error("Network error during bulk query")
      }
      return originalFetch(url, options)
    }
    // @ts-expect-error - assigning mock for testing
    globalThis.fetch = mockFetch

    try {
      const packages = [
        makePackage("pkg-a", "1.0.0"),
        makePackage("pkg-b", "2.0.0"),
        makePackage("pkg-c", "3.0.0"),
      ]

      await expect(client.queryVulnerabilities(packages)).rejects.toThrow(
        "Network error during bulk query",
      )
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  test("continues on batch query failure when failOnScannerError is false", async () => {
    const client = createNpmAuditClient({
      failOnScannerError: false,
    })

    // Mock fetch to throw for bulk advisory queries
    const originalFetch = globalThis.fetch
    let queryCallCount = 0

    const mockFetch = async (url: string | Request | URL, options?: RequestInit) => {
      const urlStr = url.toString()
      if (urlStr.includes("-/npm/v1/security/advisories/bulk")) {
        queryCallCount++
        throw new Error("Network error during bulk query")
      }
      return originalFetch(url, options)
    }
    // @ts-expect-error - assigning mock for testing
    globalThis.fetch = mockFetch

    try {
      // Note: batch threshold is 1000, so 150 packages won't trigger batching
      // This test verifies non-batched path behavior
      const packages = Array.from({ length: 150 }, (_, i) =>
        makePackage(`pkg-${String(i).padStart(3, "0")}`, "1.0.0"),
      )

      // Should not throw, should return empty results
      const result = await client.queryVulnerabilities(packages)
      expect(result).toEqual([])
      expect(queryCallCount).toBeGreaterThan(0)
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  test("rethrows on batch query failure when failOnScannerError is true (batched path)", async () => {
    const client = createNpmAuditClient({
      failOnScannerError: true,
    })

    // Mock fetch to throw for bulk advisory queries
    const originalFetch = globalThis.fetch
    const mockFetch = async (url: string | Request | URL, options?: RequestInit) => {
      const urlStr = url.toString()
      if (urlStr.includes("-/npm/v1/security/advisories/bulk")) {
        throw new Error("Network error during bulk query")
      }
      return originalFetch(url, options)
    }
    // @ts-expect-error - assigning mock for testing
    globalThis.fetch = mockFetch

    try {
      // Use 1001+ packages to trigger queryInBatches() (batch threshold is 1000)
      const packages = Array.from({ length: 1001 }, (_, i) => makePackage(`pkg-${i}`, "1.0.0"))

      await expect(client.queryVulnerabilities(packages)).rejects.toThrow(
        "Network error during bulk query",
      )
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  test("continues on batch query failure when failOnScannerError is false (batched path)", async () => {
    const client = createNpmAuditClient({
      failOnScannerError: false,
    })

    // Mock fetch to throw for bulk advisory queries
    const originalFetch = globalThis.fetch
    let queryCallCount = 0

    const mockFetch = async (url: string | Request | URL, options?: RequestInit) => {
      const urlStr = url.toString()
      if (urlStr.includes("-/npm/v1/security/advisories/bulk")) {
        queryCallCount++
        throw new Error("Network error during bulk query")
      }
      return originalFetch(url, options)
    }
    // @ts-expect-error - assigning mock for testing
    globalThis.fetch = mockFetch

    try {
      // Use 1001+ packages to trigger queryInBatches() (batch threshold is 1000)
      const packages = Array.from({ length: 1001 }, (_, i) => makePackage(`pkg-${i}`, "1.0.0"))

      // Should not throw, should return empty results after all batches fail
      const result = await client.queryVulnerabilities(packages)
      expect(result).toEqual([])
      // Batching sends multiple queries with retries - at least one query should have been made
      expect(queryCallCount).toBeGreaterThan(0)
    } finally {
      globalThis.fetch = originalFetch
    }
  }, 15000) // 15s timeout for batched queries with retries
})
