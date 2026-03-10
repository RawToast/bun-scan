import { beforeEach, describe, expect, test } from "bun:test"
import { createOSVClient } from "../client.js"

describe("OSVClient strict mode behavior", () => {
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
    const client = createOSVClient({
      failOnScannerError: true,
    })

    // Mock fetch to throw for batch queries
    const originalFetch = globalThis.fetch
    const mockFetch = async (url: string | Request | URL, options?: RequestInit) => {
      const urlStr = url.toString()
      if (urlStr.includes("querybatch")) {
        throw new Error("Network error during batch query")
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
        "Network error during batch query",
      )
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  test("continues on batch query failure when failOnScannerError is false", async () => {
    // Create client with batch disabled so it uses individual queries
    // This tests the catch-and-continue behavior in queryIndividually
    const client = createOSVClient({
      failOnScannerError: false,
      osv: { disableBatch: true },
    })

    // Mock fetch to throw for individual queries
    const originalFetch = globalThis.fetch
    let queryCallCount = 0

    const mockFetch = async (url: string | Request | URL, options?: RequestInit) => {
      const urlStr = url.toString()
      // Match individual query endpoint (not batch)
      if (urlStr.includes("/query") && !urlStr.includes("querybatch")) {
        queryCallCount++
        throw new Error("Network error during query")
      }
      // Return empty results for vuln details
      if (urlStr.includes("/vulns/")) {
        return new Response(JSON.stringify({ id: "TEST-1", summary: "test" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        })
      }
      return originalFetch(url, options)
    }
    // @ts-expect-error - assigning mock for testing
    globalThis.fetch = mockFetch

    try {
      const packages = [makePackage("pkg-a", "1.0.0")]

      // Should not throw, should return empty results due to query failure being caught
      const result = await client.queryVulnerabilities(packages)
      expect(result).toEqual([])
      expect(queryCallCount).toBeGreaterThan(0)
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  test("continues on single vulnerability fetch failure when failOnScannerError is false", async () => {
    const client = createOSVClient({})

    // Mock fetch to return a valid batch response with vuln ID
    // but fail when trying to fetch the individual vulnerability
    const originalFetch = globalThis.fetch

    const mockFetch = async (url: string | Request | URL, options?: RequestInit) => {
      const urlStr = url.toString()

      // Batch query succeeds and returns a vuln ID
      if (urlStr.includes("querybatch")) {
        return new Response(
          JSON.stringify({
            results: [{ vulns: [{ id: "CVE-2024-1234" }] }],
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        )
      }

      // Individual vuln fetch fails
      if (urlStr.includes("/vulns/CVE-2024-1234")) {
        throw new Error("Failed to fetch vulnerability details")
      }

      return originalFetch(url, options)
    }
    // @ts-expect-error - assigning mock for testing
    globalThis.fetch = mockFetch

    try {
      const packages = [makePackage("pkg-a", "1.0.0")]

      // Should not throw, should return empty due to fetch failure
      const result = await client.queryVulnerabilities(packages)
      expect(result).toEqual([])
    } finally {
      globalThis.fetch = originalFetch
    }
  })
})
