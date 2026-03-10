import { beforeEach, afterEach, describe, expect, test } from "bun:test"
import type { VulnerabilitySource } from "@repo/core"
import { createOSVSource } from "../index.js"
import { setSleep, resetSleep } from "@repo/core"

describe("OSVSource", () => {
  beforeEach(() => {
    process.env.BUN_SCAN_LOG_LEVEL = "error"
    setSleep(async () => {})
  })

  afterEach(() => {
    resetSleep()
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
    process.env.BUN_SCAN_LOG_LEVEL = "error"
    setSleep(async () => {})
  })

  afterEach(() => {
    resetSleep()
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

  test("legacy createOSVSource(ignoreObject) does not throw on failure (discriminator regression)", async () => {
    // Legacy format with ignore as object (but without new format keys)
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
      if (urlStr.includes("querybatch")) {
        return new Response(
          JSON.stringify({
            results: [
              {
                vulnerabilities: [
                  {
                    id: "CVE-2024-1234",
                    summary: "Test vulnerability",
                    severity: "HIGH",
                    affected: [
                      {
                        package: { name: "pkg-a", ecosystem: "npm" },
                        ranges: [
                          { type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.0.0" }] },
                        ],
                      },
                    ],
                  },
                ],
              },
            ],
          }),
          { status: 200 },
        )
      }
      // Handle get query for vulnerability details - return empty to avoid secondary queries failing
      if (urlStr.includes("/query") && !urlStr.includes("querybatch")) {
        return new Response(JSON.stringify({}), { status: 200 })
      }
      return originalFetch(url)
    }
    try {
      const packages = [makePackage("pkg-a", "0.5.0")]
      const result = await source.scan(packages)
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
      if (urlStr.includes("querybatch")) {
        return new Response(
          JSON.stringify({
            results: [
              {
                vulnerabilities: [
                  {
                    id: "CVE-2024-5678",
                    summary: "Test vulnerability",
                    severity: "MEDIUM",
                    affected: [
                      {
                        package: { name: "pkg-a", ecosystem: "npm" },
                        ranges: [
                          { type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.0.0" }] },
                        ],
                      },
                    ],
                  },
                ],
              },
            ],
          }),
          { status: 200 },
        )
      }
      // Handle get query for vulnerability details - return empty to avoid secondary queries failing
      if (urlStr.includes("/query") && !urlStr.includes("querybatch")) {
        return new Response(JSON.stringify({}), { status: 200 })
      }
      return originalFetch(url)
    }
    try {
      const packages = [makePackage("pkg-a", "0.5.0")]
      const result = await source.scan(packages)
      expect(result).toHaveLength(0)
    } finally {
      globalThis.fetch = originalFetch
    }
  })
})
