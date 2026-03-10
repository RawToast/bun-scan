import { beforeEach, afterEach, describe, expect, test } from "bun:test"
import { createOSVClient } from "../client.js"
import { setSleep, resetSleep } from "@repo/core"

let originalLogLevel: string | undefined

describe("OSVClient strict mode behavior", () => {
  const makePackage = (name: string, version: string): Bun.Security.Package => ({
    name,
    version,
    tarball: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
    requestedRange: "*",
  })

  beforeEach(() => {
    originalLogLevel = process.env.BUN_SCAN_LOG_LEVEL
    process.env.BUN_SCAN_LOG_LEVEL = "error"
    // Stub sleep to avoid slow tests due to retries
    setSleep(async () => {})
  })

  afterEach(() => {
    resetSleep()
    if (originalLogLevel === undefined) {
      delete process.env.BUN_SCAN_LOG_LEVEL
    } else {
      process.env.BUN_SCAN_LOG_LEVEL = originalLogLevel
    }
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
    // Lenient mode: batch query failure should not throw
    const client = createOSVClient({
      failOnScannerError: false,
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
      const packages = [makePackage("pkg-a", "1.0.0"), makePackage("pkg-b", "2.0.0")]

      // Should not throw, should return empty results
      const result = await client.queryVulnerabilities(packages)
      expect(result).toEqual([])
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  test("rethrows on individual query failure when failOnScannerError is true (disableBatch: true)", async () => {
    // Create client with batch disabled so it uses individual queries (querySinglePackage path)
    const client = createOSVClient({
      failOnScannerError: true,
      osv: { disableBatch: true },
    })

    // Mock fetch to throw for individual queries
    const originalFetch = globalThis.fetch

    const mockFetch = async (url: string | Request | URL, options?: RequestInit) => {
      const urlStr = url.toString()
      // Match individual query endpoint (not batch)
      if (urlStr.includes("/query") && !urlStr.includes("querybatch")) {
        throw new Error("Network error during individual query")
      }
      return originalFetch(url, options)
    }
    // @ts-expect-error - assigning mock for testing
    globalThis.fetch = mockFetch

    try {
      const packages = [makePackage("pkg-a", "1.0.0")]

      // Should throw because strict mode is enabled
      await expect(client.queryVulnerabilities(packages)).rejects.toThrow(
        "Network error during individual query",
      )
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  test("continues on individual query failure when failOnScannerError is false (disableBatch: true)", async () => {
    // Create client with batch disabled so it uses individual queries
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

  test("rethrows on vulnerability detail fetch failure when failOnScannerError is true", async () => {
    const client = createOSVClient({
      failOnScannerError: true,
    })

    // Mock fetch to return a valid batch response with vuln ID
    // but fail when trying to fetch the individual vulnerability
    const originalFetch = globalThis.fetch

    const mockFetch = async (url: string | Request | URL, options?: RequestInit) => {
      const urlStr = url.toString()

      // Batch query succeeds and returns a vuln ID
      if (urlStr.includes("querybatch")) {
        return new Response(
          JSON.stringify({
            results: [{ vulns: [{ id: "CVE-2024-1234", modified: "2024-01-01T00:00:00Z" }] }],
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
      // Use 2+ packages to trigger batch query path (queryWithBatch -> fetchVulnerabilityDetails)
      const packages = [makePackage("pkg-a", "1.0.0"), makePackage("pkg-b", "2.0.0")]

      // Should throw in strict mode
      await expect(client.queryVulnerabilities(packages)).rejects.toThrow(
        "Failed to fetch vulnerability details",
      )
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  test("continues on vulnerability detail fetch failure when failOnScannerError is false", async () => {
    // Use 2+ packages to trigger batch query path
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
            results: [{ vulns: [{ id: "CVE-2024-1234", modified: "2024-01-01T00:00:00Z" }] }],
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
      // Use 2+ packages to trigger batch query path
      const packages = [makePackage("pkg-a", "1.0.0"), makePackage("pkg-b", "2.0.0")]

      // Should not throw, should return empty due to fetch failure
      const result = await client.queryVulnerabilities(packages)
      expect(result).toEqual([])
    } finally {
      globalThis.fetch = originalFetch
    }
  })
})
