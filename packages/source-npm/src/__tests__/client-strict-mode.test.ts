import { beforeEach, describe, expect, test } from "bun:test"
import { createNpmAuditClient } from "../client.js"

describe("NpmAuditClient strict mode behavior", () => {
  const makePackage = (name: string, version: string): Bun.Security.Package => ({
    name,
    version,
    tarball: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
    requestedRange: "*",
  })

  beforeEach(() => {
    process.env.BUN_SCAN_LOG_LEVEL = "error"
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
      // Need many packages to trigger batched queries
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
})
