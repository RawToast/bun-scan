import { describe, expect, test } from "bun:test"
import { mapSeverityToLevel } from "../severity.js"
import type { OSVVulnerability } from "../schema.js"

describe("mapSeverityToLevel", () => {
  describe("database_specific.severity", () => {
    test("returns fatal for CRITICAL severity", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-001",
        database_specific: { severity: "CRITICAL" },
      }
      expect(mapSeverityToLevel(vuln)).toBe("fatal")
    })

    test("returns fatal for HIGH severity", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-002",
        database_specific: { severity: "HIGH" },
      }
      expect(mapSeverityToLevel(vuln)).toBe("fatal")
    })

    test("returns warn for MEDIUM severity", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-003",
        database_specific: { severity: "MEDIUM" },
      }
      expect(mapSeverityToLevel(vuln)).toBe("warn")
    })

    test("returns warn for LOW severity", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-004",
        database_specific: { severity: "LOW" },
      }
      expect(mapSeverityToLevel(vuln)).toBe("warn")
    })

    test("returns warn for unknown severity", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-005",
        database_specific: { severity: "UNKNOWN" },
      }
      expect(mapSeverityToLevel(vuln)).toBe("warn")
    })
  })

  describe("CVSS scores", () => {
    test("returns fatal for CVSS score >= 7.0", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-006",
        severity: [{ type: "CVSS_V3", score: "7.5" }],
      }
      expect(mapSeverityToLevel(vuln)).toBe("fatal")
    })

    test("returns warn for CVSS score < 7.0", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-007",
        severity: [{ type: "CVSS_V3", score: "6.9" }],
      }
      expect(mapSeverityToLevel(vuln)).toBe("warn")
    })

    test("returns fatal for exactly 7.0", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-008",
        severity: [{ type: "CVSS_V3", score: "7.0" }],
      }
      expect(mapSeverityToLevel(vuln)).toBe("fatal")
    })

    test("uses highest CVSS score when multiple present", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-009",
        severity: [
          { type: "CVSS_V2", score: "5.0" },
          { type: "CVSS_V3", score: "8.0" },
        ],
      }
      expect(mapSeverityToLevel(vuln)).toBe("fatal")
    })

    test("handles CVSS vector strings", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-010",
        severity: [
          {
            type: "CVSS_V3",
            score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/9.8",
          },
        ],
      }
      expect(mapSeverityToLevel(vuln)).toBe("fatal")
    })
  })

  describe("priority", () => {
    test("database_specific takes precedence over CVSS", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-011",
        database_specific: { severity: "LOW" },
        severity: [{ type: "CVSS_V3", score: "9.0" }],
      }
      // database_specific.severity is LOW (not fatal), so we fall through to CVSS
      expect(mapSeverityToLevel(vuln)).toBe("fatal")
    })

    test("uses CVSS when database_specific severity is fatal", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-012",
        database_specific: { severity: "CRITICAL" },
        severity: [{ type: "CVSS_V3", score: "3.0" }],
      }
      // database_specific.severity is CRITICAL (fatal), returns fatal immediately
      expect(mapSeverityToLevel(vuln)).toBe("fatal")
    })
  })

  describe("defaults", () => {
    test("returns warn when no severity info", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-013",
      }
      expect(mapSeverityToLevel(vuln)).toBe("warn")
    })

    test("returns warn for empty database_specific", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-014",
        database_specific: {},
      }
      expect(mapSeverityToLevel(vuln)).toBe("warn")
    })

    test("returns warn for non-CVSS severity types", () => {
      const vuln: OSVVulnerability = {
        id: "TEST-015",
        severity: [{ type: "OTHER", score: "severe" }],
      }
      expect(mapSeverityToLevel(vuln)).toBe("warn")
    })
  })
})
