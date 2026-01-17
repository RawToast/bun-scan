import { describe, expect, test } from "bun:test"
import {
  OSVAffectedSchema,
  OSVBatchQuerySchema,
  OSVBatchResponseSchema,
  OSVQuerySchema,
  OSVResponseSchema,
  OSVVulnerabilitySchema,
} from "~/sources/osv/schema.js"

describe("Schema Validation", () => {
  describe("OSVQuerySchema", () => {
    test("validates minimal query with package", () => {
      const query = {
        package: {
          name: "lodash",
          ecosystem: "npm",
        },
      }

      const result = OSVQuerySchema.safeParse(query)

      expect(result.success).toBe(true)
    })

    test("validates query with version", () => {
      const query = {
        package: {
          name: "express",
          ecosystem: "npm",
        },
        version: "4.17.1",
      }

      const result = OSVQuerySchema.safeParse(query)

      expect(result.success).toBe(true)
    })

    test("validates query with commit", () => {
      const query = {
        commit: "abc123def456",
      }

      const result = OSVQuerySchema.safeParse(query)

      expect(result.success).toBe(true)
    })

    test("validates query with purl", () => {
      const query = {
        package: {
          name: "lodash",
          ecosystem: "npm",
          purl: "pkg:npm/lodash@4.17.21",
        },
      }

      const result = OSVQuerySchema.safeParse(query)

      expect(result.success).toBe(true)
    })

    test("validates query with page_token", () => {
      const query = {
        package: {
          name: "lodash",
          ecosystem: "npm",
        },
        page_token: "next_page_token_123",
      }

      const result = OSVQuerySchema.safeParse(query)

      expect(result.success).toBe(true)
    })

    test("accepts empty object", () => {
      const query = {}

      const result = OSVQuerySchema.safeParse(query)

      expect(result.success).toBe(true)
    })

    test("rejects invalid package structure", () => {
      const query = {
        package: {
          name: "lodash",
          // missing ecosystem
        },
      }

      const result = OSVQuerySchema.safeParse(query)

      expect(result.success).toBe(false)
    })
  })

  describe("OSVAffectedSchema", () => {
    test("validates minimal affected package", () => {
      const affected = {
        package: {
          name: "lodash",
          ecosystem: "npm",
        },
      }

      const result = OSVAffectedSchema.safeParse(affected)

      expect(result.success).toBe(true)
    })

    test("validates affected with versions list", () => {
      const affected = {
        package: {
          name: "lodash",
          ecosystem: "npm",
        },
        versions: ["4.17.0", "4.17.1", "4.17.2"],
      }

      const result = OSVAffectedSchema.safeParse(affected)

      expect(result.success).toBe(true)
    })

    test("validates affected with ranges", () => {
      const affected = {
        package: {
          name: "lodash",
          ecosystem: "npm",
        },
        ranges: [
          {
            type: "SEMVER",
            events: [{ introduced: "0" }, { fixed: "4.17.21" }],
          },
        ],
      }

      const result = OSVAffectedSchema.safeParse(affected)

      expect(result.success).toBe(true)
    })

    test("validates range with last_affected", () => {
      const affected = {
        package: {
          name: "express",
          ecosystem: "npm",
        },
        ranges: [
          {
            type: "SEMVER",
            events: [{ introduced: "4.0.0" }, { last_affected: "4.16.4" }],
          },
        ],
      }

      const result = OSVAffectedSchema.safeParse(affected)

      expect(result.success).toBe(true)
    })

    test("validates multiple ranges", () => {
      const affected = {
        package: {
          name: "package",
          ecosystem: "npm",
        },
        ranges: [
          {
            type: "SEMVER",
            events: [{ introduced: "1.0.0" }, { fixed: "1.5.0" }],
          },
          {
            type: "SEMVER",
            events: [{ introduced: "2.0.0" }, { fixed: "2.3.0" }],
          },
        ],
      }

      const result = OSVAffectedSchema.safeParse(affected)

      expect(result.success).toBe(true)
    })

    test("validates ecosystem_specific", () => {
      const affected = {
        package: {
          name: "package",
          ecosystem: "npm",
        },
        ecosystem_specific: {
          severity: "high",
          custom_field: "value",
        },
      }

      const result = OSVAffectedSchema.safeParse(affected)

      expect(result.success).toBe(true)
    })

    test("validates database_specific", () => {
      const affected = {
        package: {
          name: "package",
          ecosystem: "npm",
        },
        database_specific: {
          source: "GitHub",
          last_known_affected_version_range: "<= 1.2.3",
        },
      }

      const result = OSVAffectedSchema.safeParse(affected)

      expect(result.success).toBe(true)
    })

    test("rejects missing package", () => {
      const affected = {
        versions: ["1.0.0"],
      }

      const result = OSVAffectedSchema.safeParse(affected)

      expect(result.success).toBe(false)
    })

    test("rejects invalid package name", () => {
      const affected = {
        package: {
          ecosystem: "npm",
          // missing name
        },
      }

      const result = OSVAffectedSchema.safeParse(affected)

      expect(result.success).toBe(false)
    })
  })

  describe("OSVVulnerabilitySchema", () => {
    test("validates minimal vulnerability", () => {
      const vuln = {
        id: "GHSA-xxxx-yyyy-zzzz",
      }

      const result = OSVVulnerabilitySchema.safeParse(vuln)

      expect(result.success).toBe(true)
    })

    test("validates full vulnerability", () => {
      const vuln = {
        id: "GHSA-1234-5678-9012",
        summary: "Prototype pollution vulnerability",
        details: "Detailed description of the vulnerability",
        modified: "2024-01-15T10:00:00Z",
        published: "2024-01-01T00:00:00Z",
        aliases: ["CVE-2024-12345"],
        affected: [
          {
            package: {
              name: "lodash",
              ecosystem: "npm",
            },
            ranges: [
              {
                type: "SEMVER",
                events: [{ introduced: "0" }, { fixed: "4.17.21" }],
              },
            ],
          },
        ],
        references: [
          {
            type: "ADVISORY",
            url: "https://github.com/advisories/GHSA-1234-5678-9012",
          },
        ],
        severity: [
          {
            type: "CVSS_V3",
            score: "7.5",
          },
        ],
      }

      const result = OSVVulnerabilitySchema.safeParse(vuln)

      expect(result.success).toBe(true)
    })

    test("validates withdrawn vulnerability", () => {
      const vuln = {
        id: "GHSA-withdrawn-test",
        withdrawn: "2024-02-01T00:00:00Z",
      }

      const result = OSVVulnerabilitySchema.safeParse(vuln)

      expect(result.success).toBe(true)
    })

    test("validates related vulnerabilities", () => {
      const vuln = {
        id: "GHSA-main",
        related: ["GHSA-related-1", "GHSA-related-2"],
      }

      const result = OSVVulnerabilitySchema.safeParse(vuln)

      expect(result.success).toBe(true)
    })

    test("validates multiple references", () => {
      const vuln = {
        id: "CVE-2024-12345",
        references: [
          {
            type: "ADVISORY",
            url: "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
          },
          {
            type: "WEB",
            url: "https://example.com/security-advisory",
          },
          {
            url: "https://github.com/repo/issues/123",
          },
        ],
      }

      const result = OSVVulnerabilitySchema.safeParse(vuln)

      expect(result.success).toBe(true)
    })

    test("validates multiple severity scores", () => {
      const vuln = {
        id: "GHSA-multi-severity",
        severity: [
          {
            type: "CVSS_V2",
            score: "6.5",
          },
          {
            type: "CVSS_V3",
            score: "7.5",
          },
        ],
      }

      const result = OSVVulnerabilitySchema.safeParse(vuln)

      expect(result.success).toBe(true)
    })

    test("validates credits", () => {
      const vuln = {
        id: "GHSA-with-credits",
        credits: [
          {
            name: "Security Researcher",
            contact: ["researcher@example.com"],
            type: "FINDER",
          },
        ],
      }

      const result = OSVVulnerabilitySchema.safeParse(vuln)

      expect(result.success).toBe(true)
    })

    test("validates database_specific fields", () => {
      const vuln = {
        id: "GHSA-db-specific",
        database_specific: {
          severity: "HIGH",
          cwe_ids: ["CWE-79", "CWE-89"],
          github_reviewed: true,
        },
      }

      const result = OSVVulnerabilitySchema.safeParse(vuln)

      expect(result.success).toBe(true)
    })

    test("validates ecosystem_specific fields", () => {
      const vuln = {
        id: "GHSA-ecosystem",
        ecosystem_specific: {
          affects: {
            arch: ["x86_64"],
            functions: ["vulnerable_function"],
          },
        },
      }

      const result = OSVVulnerabilitySchema.safeParse(vuln)

      expect(result.success).toBe(true)
    })

    test("rejects vulnerability without id", () => {
      const vuln = {
        summary: "Missing ID",
      }

      const result = OSVVulnerabilitySchema.safeParse(vuln)

      expect(result.success).toBe(false)
    })

    test("rejects invalid reference (missing url)", () => {
      const vuln = {
        id: "GHSA-bad-ref",
        references: [
          {
            type: "WEB",
            // missing url
          },
        ],
      }

      const result = OSVVulnerabilitySchema.safeParse(vuln)

      expect(result.success).toBe(false)
    })
  })

  describe("OSVResponseSchema", () => {
    test("validates empty response", () => {
      const response = {}

      const result = OSVResponseSchema.safeParse(response)

      expect(result.success).toBe(true)
    })

    test("validates response with vulns", () => {
      const response = {
        vulns: [
          {
            id: "GHSA-1234-5678-9012",
          },
          {
            id: "CVE-2024-12345",
          },
        ],
      }

      const result = OSVResponseSchema.safeParse(response)

      expect(result.success).toBe(true)
    })

    test("validates response with next_page_token", () => {
      const response = {
        vulns: [
          {
            id: "GHSA-1",
          },
        ],
        next_page_token: "token_for_next_page",
      }

      const result = OSVResponseSchema.safeParse(response)

      expect(result.success).toBe(true)
    })

    test("validates response with no vulnerabilities", () => {
      const response = {
        vulns: [],
      }

      const result = OSVResponseSchema.safeParse(response)

      expect(result.success).toBe(true)
    })
  })

  describe("OSVBatchQuerySchema", () => {
    test("validates batch query with single query", () => {
      const batchQuery = {
        queries: [
          {
            package: {
              name: "lodash",
              ecosystem: "npm",
            },
            version: "4.17.19",
          },
        ],
      }

      const result = OSVBatchQuerySchema.safeParse(batchQuery)

      expect(result.success).toBe(true)
    })

    test("validates batch query with multiple queries", () => {
      const batchQuery = {
        queries: [
          {
            package: {
              name: "lodash",
              ecosystem: "npm",
            },
            version: "4.17.19",
          },
          {
            package: {
              name: "express",
              ecosystem: "npm",
            },
            version: "4.17.1",
          },
          {
            commit: "abc123",
          },
        ],
      }

      const result = OSVBatchQuerySchema.safeParse(batchQuery)

      expect(result.success).toBe(true)
    })

    test("validates empty queries array", () => {
      const batchQuery = {
        queries: [],
      }

      const result = OSVBatchQuerySchema.safeParse(batchQuery)

      expect(result.success).toBe(true)
    })

    test("rejects missing queries field", () => {
      const batchQuery = {}

      const result = OSVBatchQuerySchema.safeParse(batchQuery)

      expect(result.success).toBe(false)
    })

    test("rejects invalid queries type", () => {
      const batchQuery = {
        queries: "not an array",
      }

      const result = OSVBatchQuerySchema.safeParse(batchQuery)

      expect(result.success).toBe(false)
    })
  })

  describe("OSVBatchResponseSchema", () => {
    test("validates batch response with results", () => {
      const response = {
        results: [
          {
            vulns: [
              {
                id: "GHSA-1234",
                modified: "2024-01-01T00:00:00Z",
              },
            ],
          },
          {
            vulns: [],
          },
        ],
      }

      const result = OSVBatchResponseSchema.safeParse(response)

      expect(result.success).toBe(true)
    })

    test("validates batch response with next_page_token", () => {
      const response = {
        results: [
          {
            vulns: [
              {
                id: "GHSA-1",
                modified: "2024-01-01T00:00:00Z",
              },
            ],
            next_page_token: "next_token",
          },
        ],
      }

      const result = OSVBatchResponseSchema.safeParse(response)

      expect(result.success).toBe(true)
    })

    test("validates empty results", () => {
      const response = {
        results: [],
      }

      const result = OSVBatchResponseSchema.safeParse(response)

      expect(result.success).toBe(true)
    })

    test("validates results with no vulnerabilities", () => {
      const response = {
        results: [
          {},
          {
            vulns: [],
          },
        ],
      }

      const result = OSVBatchResponseSchema.safeParse(response)

      expect(result.success).toBe(true)
    })

    test("rejects missing results field", () => {
      const response = {}

      const result = OSVBatchResponseSchema.safeParse(response)

      expect(result.success).toBe(false)
    })

    test("rejects invalid vuln in batch response (missing id)", () => {
      const response = {
        results: [
          {
            vulns: [
              {
                modified: "2024-01-01T00:00:00Z",
                // missing id
              },
            ],
          },
        ],
      }

      const result = OSVBatchResponseSchema.safeParse(response)

      expect(result.success).toBe(false)
    })

    test("rejects invalid vuln in batch response (missing modified)", () => {
      const response = {
        results: [
          {
            vulns: [
              {
                id: "GHSA-1234",
                // missing modified
              },
            ],
          },
        ],
      }

      const result = OSVBatchResponseSchema.safeParse(response)

      expect(result.success).toBe(false)
    })
  })

  describe("Real-World OSV Data", () => {
    test("validates real GitHub Security Advisory", () => {
      const vuln = {
        id: "GHSA-c3h9-896r-86jm",
        summary: "lodash Prototype Pollution vulnerability",
        details: "Versions of lodash before 4.17.19 are vulnerable to Prototype Pollution...",
        modified: "2023-09-12T19:52:50Z",
        published: "2020-05-08T18:45:51Z",
        aliases: ["CVE-2019-10744"],
        affected: [
          {
            package: {
              name: "lodash",
              ecosystem: "npm",
            },
            ranges: [
              {
                type: "SEMVER",
                events: [
                  {
                    introduced: "0",
                  },
                  {
                    fixed: "4.17.19",
                  },
                ],
              },
            ],
            database_specific: {
              source:
                "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2020/05/GHSA-c3h9-896r-86jm/GHSA-c3h9-896r-86jm.json",
            },
          },
        ],
        references: [
          {
            type: "ADVISORY",
            url: "https://nvd.nist.gov/vuln/detail/CVE-2019-10744",
          },
          {
            type: "WEB",
            url: "https://github.com/lodash/lodash/issues/4348",
          },
        ],
        database_specific: {
          severity: "CRITICAL",
          cwe_ids: ["CWE-1321"],
          github_reviewed: true,
        },
      }

      const result = OSVVulnerabilitySchema.safeParse(vuln)

      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.id).toBe("GHSA-c3h9-896r-86jm")
        expect(result.data.aliases).toContain("CVE-2019-10744")
      }
    })

    test("validates OSV batch response format", () => {
      const response = {
        results: [
          {
            vulns: [
              {
                id: "GHSA-1",
                modified: "2024-01-01T00:00:00Z",
              },
              {
                id: "GHSA-2",
                modified: "2024-01-02T00:00:00Z",
              },
            ],
          },
          {
            vulns: [],
          },
          {
            vulns: [
              {
                id: "CVE-2024-12345",
                modified: "2024-01-03T00:00:00Z",
              },
            ],
          },
        ],
      }

      const result = OSVBatchResponseSchema.safeParse(response)

      expect(result.success).toBe(true)
    })
  })

  describe("Type Inference", () => {
    test("infers correct types from schemas", () => {
      const query = {
        package: {
          name: "test",
          ecosystem: "npm",
        },
        version: "1.0.0",
      }

      const result = OSVQuerySchema.parse(query)

      // TypeScript should infer the correct type
      expect(result.package?.name).toBe("test")
      expect(result.version).toBe("1.0.0")
    })

    test("handles optional fields correctly", () => {
      const vuln = {
        id: "TEST-001",
      }

      const result = OSVVulnerabilitySchema.parse(vuln)

      expect(result.id).toBe("TEST-001")
      expect(result.summary).toBeUndefined()
      expect(result.affected).toBeUndefined()
    })
  })
})
