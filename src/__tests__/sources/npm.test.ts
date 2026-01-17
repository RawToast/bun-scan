import { beforeEach, describe, expect, test } from "bun:test"
import { NpmSource } from "~/sources/npm"
import type { VulnerabilitySource } from "~/sources/types"
import { NpmAuditResponseSchema } from "~/sources/npm/schema"

describe("NpmSource", () => {
  beforeEach(() => {
    process.env.BUN_SCAN_LOG_LEVEL = "error"
  })

  test("implements VulnerabilitySource interface", () => {
    const source: VulnerabilitySource = new NpmSource({})
    expect(source.name).toBe("npm")
    expect(typeof source.scan).toBe("function")
  })

  test("returns empty array for empty packages", async () => {
    const source = new NpmSource({})
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
