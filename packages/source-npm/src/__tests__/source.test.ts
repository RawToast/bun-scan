import { beforeEach, describe, expect, test } from "bun:test"
import type { VulnerabilitySource } from "@repo/core"
import { createNpmSource } from "../index.js"
import { NpmAuditResponseSchema } from "../schema.js"
import { createAdvisoryProcessor } from "../processor.js"

describe("NpmSource", () => {
  beforeEach(() => {
    process.env.BUN_SCAN_LOG_LEVEL = "error"
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
    process.env.BUN_SCAN_LOG_LEVEL = "error"
  })

  // Helper to create a proper Bun.Security.Package
  const makePackage = (name: string, version: string): Bun.Security.Package => ({
    name,
    version,
    tarball: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
    requestedRange: "*",
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
