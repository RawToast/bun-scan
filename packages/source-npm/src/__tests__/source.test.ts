import { beforeEach, afterEach, describe, expect, test } from "bun:test"
import type { VulnerabilitySource } from "@repo/core"
import { createNpmSource } from "../index.js"
import { NpmAuditResponseSchema } from "../schema.js"
import { createAdvisoryProcessor } from "../processor.js"
import { setSleep, resetSleep } from "@repo/core"

// Helper to create a proper Bun.Security.Package
const makePackage = (name: string, version: string): Bun.Security.Package => ({
  name,
  version,
  tarball: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
  requestedRange: "*",
})

let originalLogLevel: string | undefined

describe("NpmSource", () => {
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
    const source: VulnerabilitySource = createNpmSource({})
    expect(source.name).toBe("npm")
    expect(typeof source.scan).toBe("function")
  })

  test("returns empty array for empty packages", async () => {
    const source = createNpmSource({})
    const result = await source.scan([])
    expect(result).toEqual([])
  })
})

describe("npm bulk response parsing", () => {
  test("parses package->advisory[] response", () => {
    const response = {
      cookie: [
        {
          id: 1103907,
          url: "https://github.com/advisories/GHSA-pxg6-pf52-xh8x",
          title: "cookie accepts cookie name, path, and domain with out of bounds characters",
          severity: "low",
          vulnerable_versions: "<0.7.0",
          cwe: ["CWE-74"],
          cvss: {
            score: 0,
            vectorString: null,
          },
        },
      ],
    }

    const parsed = NpmAuditResponseSchema.parse(response)
    expect(parsed.cookie).toHaveLength(1)
  })

  test("handles null cvss.vectorString", () => {
    const response = {
      "test-pkg": [
        {
          id: 12345,
          url: "https://example.com/advisory",
          title: "Test advisory",
          severity: "high",
          vulnerable_versions: "<1.0.0",
          cvss: {
            score: 7.5,
            vectorString: null,
          },
        },
      ],
    }

    const parsed = NpmAuditResponseSchema.parse(response)
    expect(parsed["test-pkg"]).toHaveLength(1)
    expect(parsed["test-pkg"]![0]!.cvss?.vectorString).toBeNull()
  })

  test("handles missing cvss object", () => {
    const response = {
      "test-pkg": [
        {
          id: 12345,
          url: "https://example.com/advisory",
          title: "Test advisory",
          severity: "moderate",
          vulnerable_versions: ">=1.0.0 <2.0.0",
        },
      ],
    }

    const parsed = NpmAuditResponseSchema.parse(response)
    expect(parsed["test-pkg"]).toHaveLength(1)
    expect(parsed["test-pkg"]![0]!.cvss).toBeUndefined()
  })

  test("handles multiple advisories per package", () => {
    const response = {
      lodash: [
        {
          id: 1,
          url: "https://example.com/1",
          title: "First issue",
          severity: "critical",
          vulnerable_versions: "<4.17.11",
        },
        {
          id: 2,
          url: "https://example.com/2",
          title: "Second issue",
          severity: "high",
          vulnerable_versions: "<4.17.19",
        },
      ],
    }

    const parsed = NpmAuditResponseSchema.parse(response)
    expect(parsed.lodash).toHaveLength(2)
  })

  test("handles multiple packages in response", () => {
    const response = {
      lodash: [
        {
          id: 1,
          url: "https://example.com/1",
          title: "Lodash issue",
          severity: "high",
          vulnerable_versions: "<4.17.11",
        },
      ],
      underscore: [
        {
          id: 2,
          url: "https://example.com/2",
          title: "Underscore issue",
          severity: "moderate",
          vulnerable_versions: "<1.12.1",
        },
      ],
    }

    const parsed = NpmAuditResponseSchema.parse(response)
    expect(Object.keys(parsed)).toHaveLength(2)
    expect(parsed.lodash).toHaveLength(1)
    expect(parsed.underscore).toHaveLength(1)
  })

  test("handles empty response", () => {
    const response = {}
    const parsed = NpmAuditResponseSchema.parse(response)
    expect(Object.keys(parsed)).toHaveLength(0)
  })
})

describe("AdvisoryProcessor ignore configuration", () => {
  beforeEach(() => {
    originalLogLevel = process.env.BUN_SCAN_LOG_LEVEL
    process.env.BUN_SCAN_LOG_LEVEL = "error"
  })

  afterEach(() => {
    if (originalLogLevel === undefined) {
      delete process.env.BUN_SCAN_LOG_LEVEL
    } else {
      process.env.BUN_SCAN_LOG_LEVEL = originalLogLevel
    }
  })

  test("ignores globally ignored advisories by id", () => {
    const processor = createAdvisoryProcessor({ ignore: ["1103907"] })
    const advisories = [
      {
        id: 1103907,
        title: "Test advisory",
        severity: "low" as const,
        vulnerable_versions: "<1.0.0",
        url: "https://example.com",
        name: "test-pkg",
      },
    ]
    const packages = [makePackage("test-pkg", "0.5.0")]

    const result = processor.processAdvisories(advisories, packages)
    expect(result).toHaveLength(0)
  })

  test("ignores globally ignored advisories by CVE alias", () => {
    const processor = createAdvisoryProcessor({ ignore: ["CVE-2024-1234"] })
    const advisories = [
      {
        id: 1103907,
        title: "Test advisory",
        severity: "low" as const,
        vulnerable_versions: "<1.0.0",
        url: "https://example.com",
        name: "test-pkg",
        cves: ["CVE-2024-1234"],
      },
    ]
    const packages = [makePackage("test-pkg", "0.5.0")]

    const result = processor.processAdvisories(advisories, packages)
    expect(result).toHaveLength(0)
  })

  test("ignores globally ignored advisories by GHSA alias", () => {
    const processor = createAdvisoryProcessor({ ignore: ["GHSA-xxxx-xxxx-xxxx"] })
    const advisories = [
      {
        id: 1103907,
        title: "Test advisory",
        severity: "low" as const,
        vulnerable_versions: "<1.0.0",
        url: "https://example.com",
        name: "test-pkg",
        github_advisory_id: "GHSA-xxxx-xxxx-xxxx",
      },
    ]
    const packages = [makePackage("test-pkg", "0.5.0")]

    const result = processor.processAdvisories(advisories, packages)
    expect(result).toHaveLength(0)
  })

  test("ignores package-specific vulnerabilities", () => {
    const processor = createAdvisoryProcessor({
      packages: {
        "test-pkg": {
          vulnerabilities: ["CVE-2024-1234"],
          reason: "Not affected in our usage",
        },
      },
    })
    const advisories = [
      {
        id: 1103907,
        title: "Test advisory",
        severity: "low" as const,
        vulnerable_versions: "<1.0.0",
        url: "https://example.com",
        name: "test-pkg",
        cves: ["CVE-2024-1234"],
      },
    ]
    const packages = [makePackage("test-pkg", "0.5.0")]

    const result = processor.processAdvisories(advisories, packages)
    expect(result).toHaveLength(0)
  })

  test("ignores package-specific vulnerabilities by GHSA URL", () => {
    const processor = createAdvisoryProcessor({
      packages: {
        "test-pkg": {
          vulnerabilities: ["GHSA-3vhc-576x-3qv4"],
          reason: "Not affected in our usage",
        },
      },
    })
    const advisories = [
      {
        id: 1112134,
        title: "Test advisory",
        severity: "high" as const,
        vulnerable_versions: "<4.11.4",
        url: "https://github.com/advisories/GHSA-3vhc-576x-3qv4",
        name: "test-pkg",
      },
    ]
    const packages = [makePackage("test-pkg", "4.11.0")]

    const result = processor.processAdvisories(advisories, packages)
    expect(result).toHaveLength(0)
  })

  test("does not ignore non-matching advisories", () => {
    const processor = createAdvisoryProcessor({ ignore: ["CVE-9999-9999"] })
    const advisories = [
      {
        id: 1103907,
        title: "Test advisory",
        severity: "low" as const,
        vulnerable_versions: "<1.0.0",
        url: "https://example.com",
        name: "test-pkg",
        cves: ["CVE-2024-1234"],
      },
    ]
    const packages = [makePackage("test-pkg", "0.5.0")]

    const result = processor.processAdvisories(advisories, packages)
    expect(result).toHaveLength(1)
  })

  test("includes aliases in returned advisory", () => {
    const processor = createAdvisoryProcessor({})
    const advisories = [
      {
        id: 1103907,
        title: "Test advisory",
        severity: "low" as const,
        vulnerable_versions: "<1.0.0",
        url: "https://example.com",
        name: "test-pkg",
        cves: ["CVE-2024-1234", "CVE-2024-5678"],
        github_advisory_id: "GHSA-xxxx-xxxx-xxxx",
      },
    ]
    const packages = [makePackage("test-pkg", "0.5.0")]

    const result = processor.processAdvisories(advisories, packages)
    expect(result).toHaveLength(1)
    expect(result[0]!.aliases).toEqual(["CVE-2024-1234", "CVE-2024-5678", "GHSA-xxxx-xxxx-xxxx"])
  })

  test("handles advisory with no aliases", () => {
    const processor = createAdvisoryProcessor({})
    const advisories = [
      {
        id: 1103907,
        title: "Test advisory",
        severity: "low" as const,
        vulnerable_versions: "<1.0.0",
        url: "https://example.com",
        name: "test-pkg",
      },
    ]
    const packages = [makePackage("test-pkg", "0.5.0")]

    const result = processor.processAdvisories(advisories, packages)
    expect(result).toHaveLength(1)
    expect(result[0]!.aliases).toEqual([])
  })
})

describe("NpmSource discriminator regression tests", () => {
  // Helper to mock bulk fetch - supports error throw or success response
  const withMockedBulkFetch = async (
    options: { error: string } | { response: Record<string, unknown> },
    fn: () => Promise<unknown>,
  ): Promise<void> => {
    const originalFetch = globalThis.fetch
    const mockFetch = async (url: string | Request | URL, _options?: RequestInit) => {
      const urlStr = url.toString()
      if (urlStr.includes("-/npm/v1/security/advisories/bulk")) {
        if ("error" in options) {
          throw new Error(options.error)
        }
        return new Response(JSON.stringify(options.response), { status: 200 })
      }
      return originalFetch(url, _options)
    }
    // @ts-expect-error - assigning mock for testing
    globalThis.fetch = mockFetch

    try {
      await fn()
    } finally {
      globalThis.fetch = originalFetch
    }
  }

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

  test("createNpmSource({ failOnScannerError: true }) throws on bulk query failure", async () => {
    const source = createNpmSource({ failOnScannerError: true })
    const packages = [makePackage("pkg-a", "1.0.0"), makePackage("pkg-b", "2.0.0")]

    await withMockedBulkFetch({ error: "Network error during bulk query" }, async () => {
      // Should throw because failOnScannerError was correctly passed through via discriminator
      await expect(source.scan(packages)).rejects.toThrow("Network error during bulk query")
    })
  })

  test("createNpmSource({ failOnScannerError: false }) continues on bulk query failure", async () => {
    const source = createNpmSource({ failOnScannerError: false })
    const packages = [makePackage("pkg-a", "1.0.0"), makePackage("pkg-b", "2.0.0")]

    await withMockedBulkFetch({ error: "Network error during bulk query" }, async () => {
      // Should not throw, should return empty results
      const result = await source.scan(packages)
      expect(result).toEqual([])
    })
  })

  test("createNpmSource({ failOnScannerError: true, npm: {...} }) throws on bulk query failure", async () => {
    const source = createNpmSource({ failOnScannerError: true, npm: { timeoutMs: 30000 } })
    const packages = [makePackage("pkg-a", "1.0.0")]

    await withMockedBulkFetch({ error: "Network error during bulk query" }, async () => {
      // Should throw because failOnScannerError was correctly passed through
      await expect(source.scan(packages)).rejects.toThrow("Network error during bulk query")
    })
  })

  test("legacy createNpmSource({ ignore: [...] }) does not throw on failure (discriminator regression)", async () => {
    // This tests that legacy format (plain IgnoreConfig) is correctly identified
    // and failOnScannerError is NOT set (defaults to undefined/false)
    const source = createNpmSource({ ignore: ["CVE-2024-1234"] }) // Legacy: ignore as array
    const packages = [makePackage("pkg-a", "1.0.0")]

    await withMockedBulkFetch({ error: "Network error during bulk query" }, async () => {
      // Legacy format should NOT throw (failOnScannerError is undefined/false by default)
      const result = await source.scan(packages)
      expect(result).toEqual([])
    })
  })

  test("legacy createNpmSource(ignoreObject) does not throw on failure (discriminator regression)", async () => {
    // Legacy format with ignore as object (but without new format keys)
    const source = createNpmSource({ packages: { "pkg-a": { vulnerabilities: [] } } })
    const packages = [makePackage("pkg-a", "1.0.0")]

    await withMockedBulkFetch({ error: "Network error during bulk query" }, async () => {
      // Legacy format should NOT throw (failOnScannerError is undefined/false by default)
      const result = await source.scan(packages)
      expect(result).toEqual([])
    })
  })

  test("mixed legacy ignore array with failOnScannerError preserves ignore config", async () => {
    const source = createNpmSource({ ignore: ["CVE-2024-1234"], failOnScannerError: true })
    const packages = [makePackage("pkg-a", "0.5.0")]

    await withMockedBulkFetch(
      {
        response: {
          "pkg-a": [
            {
              id: 999999,
              url: "https://example.com/advisories/CVE-2024-1234",
              title: "Test",
              severity: "high",
              vulnerable_versions: "<1.0.0",
              cves: ["CVE-2024-1234"],
            },
          ],
        },
      },
      async () => {
        const result = await source.scan(packages)
        expect(result).toHaveLength(0)
      },
    )
  })

  test("mixed legacy packages config with failOnScannerError preserves packages config", async () => {
    const source = createNpmSource({
      packages: { "pkg-a": { vulnerabilities: ["CVE-2024-5678"] } },
      failOnScannerError: true,
    })
    const packages = [makePackage("pkg-a", "0.5.0")]

    await withMockedBulkFetch(
      {
        response: {
          "pkg-a": [
            {
              id: 999998,
              url: "https://example.com/advisories/CVE-2024-5678",
              title: "Test",
              severity: "moderate",
              vulnerable_versions: "<1.0.0",
              cves: ["CVE-2024-5678"],
            },
          ],
        },
      },
      async () => {
        const result = await source.scan(packages)
        expect(result).toHaveLength(0)
      },
    )
  })

  // Failure-path regression tests: verify failOnScannerError survives in mixed calls
  test("mixed legacy ignore array with failOnScannerError rejects on failure", async () => {
    const source = createNpmSource({ ignore: ["CVE-2024-1234"], failOnScannerError: true })
    const packages = [makePackage("pkg-a", "0.5.0")]

    // Should throw even with ignore config present
    await withMockedBulkFetch({ error: "Network error during bulk query" }, async () => {
      await expect(source.scan(packages)).rejects.toThrow("Network error during bulk query")
    })
  })

  test("mixed legacy packages config with failOnScannerError rejects on failure", async () => {
    const source = createNpmSource({
      packages: { "pkg-a": { vulnerabilities: ["CVE-2024-5678"] } },
      failOnScannerError: true,
    })
    const packages = [makePackage("pkg-a", "0.5.0")]

    // Should throw even with packages config present
    await withMockedBulkFetch({ error: "Network error during bulk query" }, async () => {
      await expect(source.scan(packages)).rejects.toThrow("Network error during bulk query")
    })
  })
})
