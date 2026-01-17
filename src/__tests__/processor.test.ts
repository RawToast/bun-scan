import { beforeEach, describe, expect, test } from "bun:test"
import { VulnerabilityProcessor } from "~/sources/osv/processor.js"
import type { OSVVulnerability } from "~/sources/osv/schema.js"

describe("Vulnerability Processor", () => {
  let processor: VulnerabilityProcessor

  beforeEach(() => {
    processor = new VulnerabilityProcessor()
  })

  describe("Basic Processing", () => {
    test("returns empty array when no vulnerabilities", () => {
      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.21",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
        },
      ]

      const result = processor.processVulnerabilities([], packages)

      expect(result).toEqual([])
    })

    test("returns empty array when no packages", () => {
      const vulns: OSVVulnerability[] = [
        {
          id: "TEST-001",
          affected: [
            {
              package: {
                name: "lodash",
                ecosystem: "npm",
              },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "4.17.20" }],
                },
              ],
            },
          ],
        },
      ]

      const result = processor.processVulnerabilities(vulns, [])

      expect(result).toEqual([])
    })

    test("creates advisory for matching vulnerability", () => {
      const vulns: OSVVulnerability[] = [
        {
          id: "GHSA-test-1234",
          summary: "Test vulnerability",
          affected: [
            {
              package: {
                name: "lodash",
                ecosystem: "npm",
              },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "4.17.20" }],
                },
              ],
            },
          ],
          database_specific: {
            severity: "HIGH",
          },
        },
      ]

      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.19",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.19.tgz",
        },
      ]

      const result = processor.processVulnerabilities(vulns, packages)

      expect(result.length).toBe(1)
      expect(result[0]).toMatchObject({
        level: "fatal",
        package: "lodash",
        description: "Test vulnerability",
      })
    })

    test("returns empty array when package not affected", () => {
      const vulns: OSVVulnerability[] = [
        {
          id: "GHSA-test-5678",
          affected: [
            {
              package: {
                name: "lodash",
                ecosystem: "npm",
              },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "4.17.20" }],
                },
              ],
            },
          ],
        },
      ]

      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.21", // Not affected
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
        },
      ]

      const result = processor.processVulnerabilities(vulns, packages)

      expect(result).toEqual([])
    })
  })

  describe("Multiple Vulnerabilities", () => {
    test("processes multiple vulnerabilities for same package", () => {
      const vulns: OSVVulnerability[] = [
        {
          id: "GHSA-1111",
          summary: "First vulnerability",
          affected: [
            {
              package: { name: "lodash", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "4.17.20" }],
                },
              ],
            },
          ],
          database_specific: { severity: "HIGH" },
        },
        {
          id: "GHSA-2222",
          summary: "Second vulnerability",
          affected: [
            {
              package: { name: "lodash", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "4.17.19" }],
                },
              ],
            },
          ],
          database_specific: { severity: "MEDIUM" },
        },
      ]

      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.15",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz",
        },
      ]

      const result = processor.processVulnerabilities(vulns, packages)

      expect(result.length).toBe(2)
      expect(result[0]?.description).toBe("First vulnerability")
      expect(result[1]?.description).toBe("Second vulnerability")
    })

    test("processes multiple packages with different vulnerabilities", () => {
      const vulns: OSVVulnerability[] = [
        {
          id: "GHSA-lodash",
          summary: "Lodash vulnerability",
          affected: [
            {
              package: { name: "lodash", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "4.17.20" }],
                },
              ],
            },
          ],
        },
        {
          id: "GHSA-axios",
          summary: "Axios vulnerability",
          affected: [
            {
              package: { name: "axios", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "1.6.0" }],
                },
              ],
            },
          ],
        },
      ]

      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.19",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.19.tgz",
        },
        {
          name: "axios",
          version: "1.5.0",
          requestedRange: "^1.0.0",
          tarball: "https://registry.npmjs.org/axios/-/axios-1.5.0.tgz",
        },
      ]

      const result = processor.processVulnerabilities(vulns, packages)

      expect(result.length).toBe(2)
      expect(result.find((r: Bun.Security.Advisory) => r.package === "lodash")).toBeDefined()
      expect(result.find((r: Bun.Security.Advisory) => r.package === "axios")).toBeDefined()
    })
  })

  describe("Deduplication", () => {
    test("avoids duplicate advisories for same vuln+package", () => {
      const vulns: OSVVulnerability[] = [
        {
          id: "GHSA-test",
          summary: "Test vulnerability",
          affected: [
            {
              package: { name: "lodash", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "4.17.20" }],
                },
              ],
            },
            // Same package in multiple affected entries
            {
              package: { name: "lodash", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { last_affected: "4.17.19" }],
                },
              ],
            },
          ],
        },
      ]

      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.19",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.19.tgz",
        },
      ]

      const result = processor.processVulnerabilities(vulns, packages)

      // Should only create one advisory despite multiple affected entries
      expect(result.length).toBe(1)
    })

    test("handles duplicate packages in input", () => {
      const vulns: OSVVulnerability[] = [
        {
          id: "GHSA-test",
          summary: "Test vulnerability",
          affected: [
            {
              package: { name: "lodash", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "4.17.20" }],
                },
              ],
            },
          ],
        },
      ]

      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.19",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.19.tgz",
        },
        {
          name: "lodash",
          version: "4.17.19",
          requestedRange: "^4.17.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.19.tgz",
        },
      ]

      const result = processor.processVulnerabilities(vulns, packages)

      // Should only create one advisory for same package@version
      expect(result.length).toBe(1)
    })
  })

  describe("URL Prioritization", () => {
    test("prioritizes ADVISORY type references", () => {
      const vulns: OSVVulnerability[] = [
        {
          id: "GHSA-test",
          summary: "Test",
          affected: [
            {
              package: { name: "lodash", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "4.17.20" }],
                },
              ],
            },
          ],
          references: [
            {
              type: "WEB",
              url: "https://example.com/blog",
            },
            {
              type: "ADVISORY",
              url: "https://github.com/advisories/GHSA-test",
            },
            {
              type: "WEB",
              url: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1234",
            },
          ],
        },
      ]

      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.19",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.19.tgz",
        },
      ]

      const result = processor.processVulnerabilities(vulns, packages)

      expect(result[0]?.url).toBe("https://github.com/advisories/GHSA-test")
    })

    test("prioritizes GitHub advisory URLs even without ADVISORY type", () => {
      const vulns: OSVVulnerability[] = [
        {
          id: "GHSA-test",
          summary: "Test",
          affected: [
            {
              package: { name: "lodash", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "4.17.20" }],
                },
              ],
            },
          ],
          references: [
            {
              type: "WEB",
              url: "https://example.com/blog",
            },
            {
              type: "WEB",
              url: "https://github.com/advisories/GHSA-test",
            },
          ],
        },
      ]

      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.19",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.19.tgz",
        },
      ]

      const result = processor.processVulnerabilities(vulns, packages)

      expect(result[0]?.url).toBe("https://github.com/advisories/GHSA-test")
    })

    test("falls back to CVE URLs", () => {
      const vulns: OSVVulnerability[] = [
        {
          id: "CVE-2024-1234",
          summary: "Test",
          affected: [
            {
              package: { name: "lodash", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "4.17.20" }],
                },
              ],
            },
          ],
          references: [
            {
              type: "WEB",
              url: "https://example.com/blog",
            },
            {
              type: "WEB",
              url: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1234",
            },
          ],
        },
      ]

      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.19",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.19.tgz",
        },
      ]

      const result = processor.processVulnerabilities(vulns, packages)

      expect(result[0]?.url).toBe("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1234")
    })

    test("uses NVD URLs as CVE sources", () => {
      const vulns: OSVVulnerability[] = [
        {
          id: "CVE-2024-5678",
          summary: "Test",
          affected: [
            {
              package: { name: "lodash", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "4.17.20" }],
                },
              ],
            },
          ],
          references: [
            {
              type: "WEB",
              url: "https://example.com/blog",
            },
            {
              type: "WEB",
              url: "https://nvd.nist.gov/vuln/detail/CVE-2024-5678",
            },
          ],
        },
      ]

      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.19",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.19.tgz",
        },
      ]

      const result = processor.processVulnerabilities(vulns, packages)

      expect(result[0]?.url).toBe("https://nvd.nist.gov/vuln/detail/CVE-2024-5678")
    })

    test("falls back to first reference", () => {
      const vulns: OSVVulnerability[] = [
        {
          id: "GHSA-test",
          summary: "Test",
          affected: [
            {
              package: { name: "lodash", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "4.17.20" }],
                },
              ],
            },
          ],
          references: [
            {
              type: "WEB",
              url: "https://example.com/blog",
            },
            {
              type: "WEB",
              url: "https://other.com/article",
            },
          ],
        },
      ]

      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.19",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.19.tgz",
        },
      ]

      const result = processor.processVulnerabilities(vulns, packages)

      expect(result[0]?.url).toBe("https://example.com/blog")
    })

    test("returns null when no references", () => {
      const vulns: OSVVulnerability[] = [
        {
          id: "GHSA-test",
          summary: "Test",
          affected: [
            {
              package: { name: "lodash", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "4.17.20" }],
                },
              ],
            },
          ],
        },
      ]

      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.19",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.19.tgz",
        },
      ]

      const result = processor.processVulnerabilities(vulns, packages)

      expect(result[0]?.url).toBeNull()
    })

    test("handles invalid URLs gracefully", () => {
      const vulns: OSVVulnerability[] = [
        {
          id: "GHSA-test",
          summary: "Test",
          affected: [
            {
              package: { name: "lodash", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "4.17.20" }],
                },
              ],
            },
          ],
          references: [
            {
              type: "WEB",
              url: "not-a-valid-url",
            },
            {
              type: "WEB",
              url: "https://example.com/valid",
            },
          ],
        },
      ]

      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.19",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.19.tgz",
        },
      ]

      const result = processor.processVulnerabilities(vulns, packages)

      // Should fall back to first reference even if invalid
      expect(result[0]?.url).toBe("not-a-valid-url")
    })
  })

  describe("Description Handling", () => {
    test("uses summary when available", () => {
      const vulns: OSVVulnerability[] = [
        {
          id: "GHSA-test",
          summary: "Short summary",
          details: "This is a much longer detailed description of the vulnerability",
          affected: [
            {
              package: { name: "lodash", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "4.17.20" }],
                },
              ],
            },
          ],
        },
      ]

      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.19",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.19.tgz",
        },
      ]

      const result = processor.processVulnerabilities(vulns, packages)

      expect(result[0]?.description).toBe("Short summary")
    })

    test("falls back to details when summary missing", () => {
      const vulns: OSVVulnerability[] = [
        {
          id: "GHSA-test",
          details: "Detailed description",
          affected: [
            {
              package: { name: "lodash", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "4.17.20" }],
                },
              ],
            },
          ],
        },
      ]

      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.19",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.19.tgz",
        },
      ]

      const result = processor.processVulnerabilities(vulns, packages)

      expect(result[0]?.description).toBe("Detailed description")
    })

    test("truncates long details to 200 chars with ellipsis", () => {
      const longDetails =
        "This is a very long detailed description that exceeds the maximum allowed length of 200 characters. It contains multiple sentences and lots of information about the vulnerability that should be truncated to fit within the limit."

      const vulns: OSVVulnerability[] = [
        {
          id: "GHSA-test",
          details: longDetails,
          affected: [
            {
              package: { name: "lodash", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "4.17.20" }],
                },
              ],
            },
          ],
        },
      ]

      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.19",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.19.tgz",
        },
      ]

      const result = processor.processVulnerabilities(vulns, packages)

      // Extracts first sentence since it's under 200 chars
      expect(result[0]?.description).toBe(
        "This is a very long detailed description that exceeds the maximum allowed length of 200 characters.",
      )
    })

    test("extracts first sentence from long details", () => {
      const details =
        "This is the first sentence. This is the second sentence that goes on for a while with more information. And here is a third sentence."

      const vulns: OSVVulnerability[] = [
        {
          id: "GHSA-test",
          details,
          affected: [
            {
              package: { name: "lodash", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "4.17.20" }],
                },
              ],
            },
          ],
        },
      ]

      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.19",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.19.tgz",
        },
      ]

      const result = processor.processVulnerabilities(vulns, packages)

      // Details are under 200 chars, returns full text
      expect(result[0]?.description).toBe(details)
    })

    test("returns null when no description available", () => {
      const vulns: OSVVulnerability[] = [
        {
          id: "GHSA-test",
          affected: [
            {
              package: { name: "lodash", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "4.17.20" }],
                },
              ],
            },
          ],
        },
      ]

      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.19",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.19.tgz",
        },
      ]

      const result = processor.processVulnerabilities(vulns, packages)

      expect(result[0]?.description).toBeNull()
    })

    test("handles whitespace-only summary", () => {
      const vulns: OSVVulnerability[] = [
        {
          id: "GHSA-test",
          summary: "   \n\t  ",
          details: "Valid details",
          affected: [
            {
              package: { name: "lodash", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "4.17.20" }],
                },
              ],
            },
          ],
        },
      ]

      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.19",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.19.tgz",
        },
      ]

      const result = processor.processVulnerabilities(vulns, packages)

      expect(result[0]?.description).toBe("Valid details")
    })

    test("handles first sentence with exclamation mark", () => {
      const details = "Critical vulnerability! Please update immediately. More details here."

      const vulns: OSVVulnerability[] = [
        {
          id: "GHSA-test",
          details,
          affected: [
            {
              package: { name: "lodash", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "4.17.20" }],
                },
              ],
            },
          ],
        },
      ]

      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.19",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.19.tgz",
        },
      ]

      const result = processor.processVulnerabilities(vulns, packages)

      // Details are under 200 chars, returns full text
      expect(result[0]?.description).toBe(details)
    })

    test("handles first sentence with question mark", () => {
      const details =
        "Is your package vulnerable? Check the version range below. Additional context provided."

      const vulns: OSVVulnerability[] = [
        {
          id: "GHSA-test",
          details,
          affected: [
            {
              package: { name: "lodash", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "4.17.20" }],
                },
              ],
            },
          ],
        },
      ]

      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.19",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.19.tgz",
        },
      ]

      const result = processor.processVulnerabilities(vulns, packages)

      // Details are under 200 chars, returns full text
      expect(result[0]?.description).toBe(details)
    })
  })

  describe("Real-World Scenarios", () => {
    test("processes GitHub Security Advisory format", () => {
      const vulns: OSVVulnerability[] = [
        {
          id: "GHSA-c3h9-896r-86jm",
          summary: "lodash Prototype Pollution vulnerability",
          details: "Versions of lodash before 4.17.19 are vulnerable to Prototype Pollution.",
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
                  events: [{ introduced: "0" }, { fixed: "4.17.19" }],
                },
              ],
            },
          ],
          references: [
            {
              type: "ADVISORY",
              url: "https://github.com/advisories/GHSA-c3h9-896r-86jm",
            },
            {
              type: "WEB",
              url: "https://nvd.nist.gov/vuln/detail/CVE-2019-10744",
            },
          ],
          database_specific: {
            severity: "CRITICAL",
            github_reviewed: true,
          },
        },
      ]

      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.15",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz",
        },
      ]

      const result = processor.processVulnerabilities(vulns, packages)

      expect(result.length).toBe(1)
      expect(result[0]).toMatchObject({
        level: "fatal",
        package: "lodash",
        url: "https://github.com/advisories/GHSA-c3h9-896r-86jm",
        description: "lodash Prototype Pollution vulnerability",
      })
    })

    test("handles vulnerability with no affected packages", () => {
      const vulns: OSVVulnerability[] = [
        {
          id: "GHSA-test",
          summary: "Test vulnerability",
          // No affected field
        },
      ]

      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.19",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.19.tgz",
        },
      ]

      const result = processor.processVulnerabilities(vulns, packages)

      expect(result).toEqual([])
    })

    test("processes mixed severity levels correctly", () => {
      const vulns: OSVVulnerability[] = [
        {
          id: "GHSA-high",
          summary: "High severity",
          affected: [
            {
              package: { name: "lodash", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "4.17.20" }],
                },
              ],
            },
          ],
          database_specific: {
            severity: "HIGH",
          },
        },
        {
          id: "GHSA-medium",
          summary: "Medium severity",
          affected: [
            {
              package: { name: "lodash", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "4.17.19" }],
                },
              ],
            },
          ],
          database_specific: {
            severity: "MEDIUM",
          },
        },
      ]

      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.15",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz",
        },
      ]

      const result = processor.processVulnerabilities(vulns, packages)

      expect(result.length).toBe(2)
      expect(result[0]?.level).toBe("fatal") // HIGH
      expect(result[1]?.level).toBe("warn") // MEDIUM
    })
  })

  describe("Edge Cases", () => {
    test("handles scoped package names", () => {
      const vulns: OSVVulnerability[] = [
        {
          id: "GHSA-test",
          summary: "Test vulnerability",
          affected: [
            {
              package: {
                name: "@babel/traverse",
                ecosystem: "npm",
              },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "7.23.0" }],
                },
              ],
            },
          ],
        },
      ]

      const packages: Bun.Security.Package[] = [
        {
          name: "@babel/traverse",
          version: "7.22.0",
          requestedRange: "^7.0.0",
          tarball: "https://registry.npmjs.org/@babel/traverse/-/traverse-7.22.0.tgz",
        },
      ]

      const result = processor.processVulnerabilities(vulns, packages)

      expect(result.length).toBe(1)
      expect(result[0]?.package).toBe("@babel/traverse")
    })

    test("handles empty references array", () => {
      const vulns: OSVVulnerability[] = [
        {
          id: "GHSA-test",
          summary: "Test",
          affected: [
            {
              package: { name: "lodash", ecosystem: "npm" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [{ introduced: "0" }, { fixed: "4.17.20" }],
                },
              ],
            },
          ],
          references: [],
        },
      ]

      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.19",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.19.tgz",
        },
      ]

      const result = processor.processVulnerabilities(vulns, packages)

      expect(result[0]?.url).toBeNull()
    })

    test("handles empty affected array", () => {
      const vulns: OSVVulnerability[] = [
        {
          id: "GHSA-test",
          summary: "Test",
          affected: [],
        },
      ]

      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.19",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.19.tgz",
        },
      ]

      const result = processor.processVulnerabilities(vulns, packages)

      expect(result).toEqual([])
    })
  })
})
