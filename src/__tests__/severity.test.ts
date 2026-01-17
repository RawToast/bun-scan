import { describe, expect, test } from "bun:test"
import { mapSeverityToLevel } from "~/severity"
import type { OSVVulnerability } from "~/schema"

describe("Severity Assessment", () => {
  describe("Database Severity Mapping", () => {
    test("maps CRITICAL to fatal", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-001",
        database_specific: {
          severity: "CRITICAL",
        },
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("fatal")
    })

    test("maps HIGH to fatal", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-002",
        database_specific: {
          severity: "HIGH",
        },
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("fatal")
    })

    test("maps MEDIUM to warn", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-003",
        database_specific: {
          severity: "MEDIUM",
        },
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("warn")
    })

    test("maps LOW to warn", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-004",
        database_specific: {
          severity: "LOW",
        },
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("warn")
    })

    test("maps unknown severity to warn", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-005",
        database_specific: {
          severity: "UNKNOWN" as unknown as string,
        },
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("warn")
    })
  })

  describe("CVSS Score Mapping", () => {
    test("maps CVSS 9.0 to fatal", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-006",
        severity: [
          {
            type: "CVSS_V3",
            score: "9.0",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("fatal")
    })

    test("maps CVSS 7.0 to fatal (threshold)", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-007",
        severity: [
          {
            type: "CVSS_V3",
            score: "7.0",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("fatal")
    })

    test("maps CVSS 6.9 to warn (below threshold)", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-008",
        severity: [
          {
            type: "CVSS_V3",
            score: "6.9",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("warn")
    })

    test("maps CVSS 3.5 to warn", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-009",
        severity: [
          {
            type: "CVSS_V3",
            score: "3.5",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("warn")
    })

    test("handles CVSS v2 scores", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-010",
        severity: [
          {
            type: "CVSS_V2",
            score: "8.5",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("fatal")
    })

    test("handles CVSS v3.1 scores", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-011",
        severity: [
          {
            type: "CVSS_V3",
            score: "7.5",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("fatal")
    })
  })

  describe("CVSS Vector String Parsing", () => {
    test("parses CVSS v3.1 vector string with score", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-012",
        severity: [
          {
            type: "CVSS_V3",
            score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/9.8",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("fatal")
    })

    test("parses CVSS v3.0 vector string", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-013",
        severity: [
          {
            type: "CVSS_V3",
            score: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/7.5",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("fatal")
    })

    test("extracts score from end of vector string", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-014",
        severity: [
          {
            type: "CVSS_V3",
            score: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/8.4",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("fatal")
    })

    test("handles vector string without explicit score at end", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-015",
        severity: [
          {
            type: "CVSS_V3",
            score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      // Without extractable score, defaults to warn
      expect(level).toBe("warn")
    })
  })

  describe("Multiple Severity Scores", () => {
    test("uses highest CVSS score when multiple present", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-016",
        severity: [
          {
            type: "CVSS_V2",
            score: "5.0",
          },
          {
            type: "CVSS_V3",
            score: "9.1",
          },
          {
            type: "CVSS_V3",
            score: "6.5",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("fatal") // 9.1 is highest
    })

    test("ignores non-CVSS severity types", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-017",
        severity: [
          {
            type: "UNKNOWN" as unknown as "CVSS_V3",
            score: "100",
          },
          {
            type: "CVSS_V3",
            score: "6.0",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("warn") // Only 6.0 CVSS score is used
    })
  })

  describe("Severity Priority", () => {
    test("database severity only takes priority if CRITICAL or HIGH", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-018",
        database_specific: {
          severity: "LOW",
        },
        severity: [
          {
            type: "CVSS_V3",
            score: "9.0",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      // LOW is not fatal, so falls through to CVSS check which returns fatal
      expect(level).toBe("fatal")
    })

    test("uses CVSS when database severity not fatal", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-019",
        database_specific: {
          severity: "MEDIUM",
        },
        severity: [
          {
            type: "CVSS_V3",
            score: "9.0",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      // MEDIUM is not fatal, falls through to CVSS 9.0 → fatal
      expect(level).toBe("fatal")
    })

    test("database CRITICAL overrides low CVSS", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-020",
        database_specific: {
          severity: "CRITICAL",
        },
        severity: [
          {
            type: "CVSS_V3",
            score: "3.0",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("fatal")
    })
  })

  describe("Edge Cases", () => {
    test("handles missing severity data", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-021",
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("warn") // Default
    })

    test("handles empty severity array", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-022",
        severity: [],
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("warn")
    })

    test("handles invalid CVSS score format", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-023",
        severity: [
          {
            type: "CVSS_V3",
            score: "invalid",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("warn")
    })

    test("handles CVSS score outside valid range (negative)", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-024",
        severity: [
          {
            type: "CVSS_V3",
            score: "-1.0",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("warn")
    })

    test("handles CVSS score outside valid range (>10)", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-025",
        severity: [
          {
            type: "CVSS_V3",
            score: "11.0",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("warn")
    })

    test("handles null database_specific", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-026",
        database_specific: null as unknown as Record<string, unknown>,
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("warn")
    })

    test("handles undefined database_specific.severity", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-027",
        database_specific: {},
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("warn")
    })

    test("handles numeric severity in database_specific", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-028",
        database_specific: {
          severity: 5 as unknown as string,
        },
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("warn") // Not a string, not recognized
    })
  })

  describe("Real-World Vulnerability Scenarios", () => {
    test("classifies RCE vulnerability as fatal", () => {
      const vuln: OSVVulnerability = {
        id: "GHSA-xxxx-yyyy-zzzz",
        database_specific: {
          severity: "CRITICAL",
        },
        severity: [
          {
            type: "CVSS_V3",
            score: "9.8",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("fatal")
    })

    test("classifies prototype pollution as appropriate level", () => {
      const vuln: OSVVulnerability = {
        id: "GHSA-1234-5678-9012",
        database_specific: {
          severity: "HIGH",
        },
        severity: [
          {
            type: "CVSS_V3",
            score: "7.5",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("fatal")
    })

    test("classifies DoS vulnerability based on severity", () => {
      const vuln: OSVVulnerability = {
        id: "CVE-2024-12345",
        database_specific: {
          severity: "MEDIUM",
        },
        severity: [
          {
            type: "CVSS_V3",
            score: "5.3",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("warn")
    })

    test("handles GitHub Security Advisory format", () => {
      const vuln: OSVVulnerability = {
        id: "GHSA-abcd-efgh-ijkl",
        database_specific: {
          severity: "CRITICAL",
          github_reviewed: true,
        },
        severity: [
          {
            type: "CVSS_V3",
            score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/9.8",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("fatal")
    })

    test("handles npm advisory format", () => {
      const vuln: OSVVulnerability = {
        id: "1234567",
        database_specific: {
          severity: "HIGH", // OSV uses uppercase
        },
        severity: [
          {
            type: "CVSS_V3",
            score: "7.3",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      // HIGH matches FATAL_SEVERITIES
      expect(level).toBe("fatal")
    })
  })

  describe("Boundary Testing", () => {
    test("CVSS 6.99 is warn", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-029",
        severity: [
          {
            type: "CVSS_V3",
            score: "6.99",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("warn")
    })

    test("CVSS 7.01 is fatal", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-030",
        severity: [
          {
            type: "CVSS_V3",
            score: "7.01",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("fatal")
    })

    test("CVSS 10.0 is fatal", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-031",
        severity: [
          {
            type: "CVSS_V3",
            score: "10.0",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("fatal")
    })

    test("CVSS 0.0 is warn", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-032",
        severity: [
          {
            type: "CVSS_V3",
            score: "0.0",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("warn")
    })
  })

  describe("Decimal Precision", () => {
    test("handles one decimal place", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-033",
        severity: [
          {
            type: "CVSS_V3",
            score: "7.5",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("fatal")
    })

    test("handles integer scores", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-034",
        severity: [
          {
            type: "CVSS_V3",
            score: "8",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("fatal")
    })

    test("handles two decimal places", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-035",
        severity: [
          {
            type: "CVSS_V3",
            score: "7.25",
          },
        ],
      }

      const level = mapSeverityToLevel(vuln)

      expect(level).toBe("fatal")
    })
  })
})
