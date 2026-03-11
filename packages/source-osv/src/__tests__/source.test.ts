import { beforeEach, afterEach, describe, expect, test } from "bun:test"
import type { VulnerabilitySource } from "@repo/core"
import { createOSVSource } from "../index.js"
import { setSleep, resetSleep } from "@repo/core"

let originalLogLevel: string | undefined

describe("OSVSource", () => {
  beforeEach(() => {
    originalLogLevel = process.env.BUN_SCAN_LOG_LEVEL
    process.env.BUN_SCAN_LOG_LEVEL = "error"
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

  test("implements VulnerabilitySource interface", () => {
    const source: VulnerabilitySource = createOSVSource({})
    expect(source.name).toBe("osv")
    expect(typeof source.scan).toBe("function")
  })

  test("returns empty array for empty packages", async () => {
    const source = createOSVSource({})
    const result = await source.scan([])
    expect(result).toEqual([])
  })
})

describe("OSVSource discriminator regression tests", () => {
  const makePackage = (name: string, version: string): Bun.Security.Package => ({
    name,
    version,
    tarball: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
    requestedRange: "*",
  })

  beforeEach(() => {
    originalLogLevel = process.env.BUN_SCAN_LOG_LEVEL
    process.env.BUN_SCAN_LOG_LEVEL = "error"
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

  test("createOSVSource({ failOnScannerError: true }) throws on batch query failure", async () => {
    const source = createOSVSource({ failOnScannerError: true })

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

      // Should throw because failOnScannerError was correctly passed through via discriminator
      await expect(source.scan(packages)).rejects.toThrow("Network error during batch query")
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  test("createOSVSource({ failOnScannerError: false }) continues on batch query failure", async () => {
    const source = createOSVSource({ failOnScannerError: false })

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
      const result = await source.scan(packages)
      expect(result).toEqual([])
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  test("createOSVSource({ failOnScannerError: true, osv: { disableBatch: true } }) throws on individual query failure", async () => {
    const source = createOSVSource({ failOnScannerError: true, osv: { disableBatch: true } })

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

      // Should throw because failOnScannerError was correctly passed through
      await expect(source.scan(packages)).rejects.toThrow("Network error during individual query")
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  test("legacy createOSVSource({ ignore: [...] }) does not throw on failure (discriminator regression)", async () => {
    // This tests that legacy format (plain IgnoreConfig) is correctly identified
    // and failOnScannerError is NOT set (defaults to undefined/false)
    const source = createOSVSource({ ignore: ["CVE-2024-1234"] }) // Legacy: ignore as array

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
      const packages = [makePackage("pkg-a", "1.0.0")]

      // Legacy format should NOT throw (failOnScannerError is undefined/false by default)
      const result = await source.scan(packages)
      expect(result).toEqual([])
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  test("legacy createOSVSource(packages) does not throw on failure (discriminator regression)", async () => {
    // Legacy format with packages (but without new format keys like failOnScannerError)
    const source = createOSVSource({ packages: { "pkg-a": { vulnerabilities: [] } } })

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
      const packages = [makePackage("pkg-a", "1.0.0")]

      // Legacy format should NOT throw (failOnScannerError is undefined/false by default)
      const result = await source.scan(packages)
      expect(result).toEqual([])
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  test("mixed legacy ignore array with failOnScannerError preserves ignore config", async () => {
    const source = createOSVSource({ ignore: ["CVE-2024-1234"], failOnScannerError: true })
    const originalFetch = globalThis.fetch
    // @ts-expect-error - assigning mock for testing
    globalThis.fetch = async (url: string | Request | URL) => {
      const urlStr = url.toString()
      // Use batch mode by providing 2+ packages - OSV only uses batch when > 1 package
      if (urlStr.includes("querybatch")) {
        return new Response(
          JSON.stringify({
            results: [
              {
                vulns: [{ id: "CVE-2024-1234", modified: "2024-01-01T00:00:00Z" }],
              },
              {
                vulns: [], // Second package has no vulns
              },
            ],
          }),
          { status: 200 },
        )
      }
      // Mock /vulns/:id endpoint for fetching full vulnerability details
      if (urlStr.includes("/vulns/")) {
        const vulnId = urlStr.split("/vulns/")[1]
        return new Response(
          JSON.stringify({
            id: vulnId,
            summary: "Test vulnerability",
            severity: [{ type: "CVSS_V3", score: "7.5" }],
            modified: "2024-01-01T00:00:00Z",
            affected: [
              {
                package: { name: "pkg-a", ecosystem: "npm" },
                ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.0.0" }] }],
              },
            ],
          }),
          { status: 200 },
        )
      }
      return originalFetch(url)
    }
    try {
      // Use 2 packages to trigger batch mode (OSV uses batch when > 1 package)
      const packages = [makePackage("pkg-a", "0.5.0"), makePackage("pkg-b", "1.0.0")]
      const result = await source.scan(packages)
      // Should be empty because CVE-2024-1234 is in the ignore list
      expect(result).toHaveLength(0)
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  test("mixed legacy packages config with failOnScannerError preserves packages config", async () => {
    const source = createOSVSource({
      packages: { "pkg-a": { vulnerabilities: ["CVE-2024-5678"] } },
      failOnScannerError: true,
    })
    const originalFetch = globalThis.fetch
    // @ts-expect-error - assigning mock for testing
    globalThis.fetch = async (url: string | Request | URL) => {
      const urlStr = url.toString()
      // Use batch mode by providing 2+ packages - OSV only uses batch when > 1 package
      if (urlStr.includes("querybatch")) {
        return new Response(
          JSON.stringify({
            results: [
              {
                vulns: [{ id: "CVE-2024-5678", modified: "2024-01-01T00:00:00Z" }],
              },
              {
                vulns: [], // Second package has no vulns
              },
            ],
          }),
          { status: 200 },
        )
      }
      // Mock /vulns/:id endpoint for fetching full vulnerability details
      if (urlStr.includes("/vulns/")) {
        const vulnId = urlStr.split("/vulns/")[1]
        return new Response(
          JSON.stringify({
            id: vulnId,
            summary: "Test vulnerability",
            severity: [{ type: "CVSS_V3", score: "5.0" }],
            modified: "2024-01-01T00:00:00Z",
            affected: [
              {
                package: { name: "pkg-a", ecosystem: "npm" },
                ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.0.0" }] }],
              },
            ],
          }),
          { status: 200 },
        )
      }
      return originalFetch(url)
    }
    try {
      // Use 2 packages to trigger batch mode (OSV uses batch when > 1 package)
      const packages = [makePackage("pkg-a", "0.5.0"), makePackage("pkg-b", "1.0.0")]
      const result = await source.scan(packages)
      // Should be empty because CVE-2024-5678 is in the packages config (pre-defined vulnerability list)
      expect(result).toHaveLength(0)
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  // Failure-path regression tests: verify failOnScannerError survives in mixed calls
  test("mixed legacy ignore array with failOnScannerError rejects on failure", async () => {
    const source = createOSVSource({ ignore: ["CVE-2024-1234"], failOnScannerError: true })
    const packages = [makePackage("pkg-a", "0.5.0")]

    // Mock fetch to throw for both batch and individual queries (single package uses /query)
    const originalFetch = globalThis.fetch
    const mockFetch = async (url: string | Request | URL, options?: RequestInit) => {
      const urlStr = url.toString()
      if (
        urlStr.includes("querybatch") ||
        (urlStr.includes("/query") && !urlStr.includes("querybatch"))
      ) {
        throw new Error("Network error during batch query")
      }
      return originalFetch(url, options)
    }
    // @ts-expect-error - assigning mock for testing
    globalThis.fetch = mockFetch

    try {
      // Should throw even with ignore config present
      await expect(source.scan(packages)).rejects.toThrow("Network error during batch query")
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  test("mixed legacy packages config with failOnScannerError rejects on failure", async () => {
    const source = createOSVSource({
      packages: { "pkg-a": { vulnerabilities: ["CVE-2024-5678"] } },
      failOnScannerError: true,
    })
    const packages = [makePackage("pkg-a", "0.5.0")]

    // Mock fetch to throw for both batch and individual queries
    const originalFetch = globalThis.fetch
    const mockFetch = async (url: string | Request | URL, options?: RequestInit) => {
      const urlStr = url.toString()
      if (
        urlStr.includes("querybatch") ||
        (urlStr.includes("/query") && !urlStr.includes("querybatch"))
      ) {
        throw new Error("Network error during batch query")
      }
      return originalFetch(url, options)
    }
    // @ts-expect-error - assigning mock for testing
    globalThis.fetch = mockFetch

    try {
      // Should throw even with packages config present
      await expect(source.scan(packages)).rejects.toThrow("Network error during batch query")
    } finally {
      globalThis.fetch = originalFetch
    }
  })
})
