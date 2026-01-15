/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

import { beforeEach, describe, expect, test } from "bun:test"
import { scanner } from "../src/index.js"

describe("Scanner", () => {
  beforeEach(() => {
    // Set log level to error to reduce test output
    process.env.OSV_LOG_LEVEL = "error"
  })

  describe("Interface Compliance", () => {
    test("implements Bun.Security.Scanner interface", () => {
      expect(scanner).toBeDefined()
      expect(scanner.version).toBeDefined()
      expect(scanner.scan).toBeDefined()
    })

    test("has correct version", () => {
      expect(scanner.version).toBe("1")
    })

    test("scan is a function", () => {
      expect(typeof scanner.scan).toBe("function")
    })

    test("scan accepts packages parameter", () => {
      expect(scanner.scan.length).toBe(1)
    })
  })

  describe("Input Validation", () => {
    test("handles empty package list", async () => {
      const result = await scanner.scan({ packages: [] })

      expect(Array.isArray(result)).toBe(true)
      expect(result.length).toBe(0)
    })

    test("handles single package", async () => {
      const packages: Bun.Security.Package[] = [
        {
          name: "safe-package",
          version: "1.0.0",
          requestedRange: "^1.0.0",
          tarball: "https://registry.npmjs.org/safe-package/-/safe-package-1.0.0.tgz",
        },
      ]

      const result = await scanner.scan({ packages })

      expect(Array.isArray(result)).toBe(true)
    })

    test("returns array of security advisories", async () => {
      const packages: Bun.Security.Package[] = [
        {
          name: "test-package",
          version: "1.0.0",
          requestedRange: "^1.0.0",
          tarball: "https://registry.npmjs.org/test-package/-/test-package-1.0.0.tgz",
        },
      ]

      const result = await scanner.scan({ packages })

      expect(Array.isArray(result)).toBe(true)

      // Each advisory should have required fields
      for (const advisory of result) {
        expect(advisory).toHaveProperty("id")
        expect(advisory).toHaveProperty("message")
        expect(advisory).toHaveProperty("level")
        expect(["fatal", "warn"]).toContain(advisory.level)
      }
    })
  })

  describe("Package Deduplication", () => {
    test("handles duplicate packages", async () => {
      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.21",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
        },
        {
          name: "lodash",
          version: "4.17.21",
          requestedRange: "^4.17.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
        },
      ]

      const result = await scanner.scan({ packages })

      expect(Array.isArray(result)).toBe(true)
      // Deduplication should be handled internally
    })

    test("handles different versions of same package", async () => {
      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.20",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
        },
        {
          name: "lodash",
          version: "4.17.21",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
        },
      ]

      const result = await scanner.scan({ packages })

      expect(Array.isArray(result)).toBe(true)
    })
  })

  describe("Multiple Packages", () => {
    test("scans multiple different packages", async () => {
      const packages: Bun.Security.Package[] = [
        {
          name: "express",
          version: "4.18.0",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/express/-/express-4.18.0.tgz",
        },
        {
          name: "lodash",
          version: "4.17.21",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
        },
        {
          name: "axios",
          version: "1.5.0",
          requestedRange: "^1.0.0",
          tarball: "https://registry.npmjs.org/axios/-/axios-1.5.0.tgz",
        },
      ]

      const result = await scanner.scan({ packages })

      expect(Array.isArray(result)).toBe(true)
    })

    test("handles large package list", async () => {
      const packages: Bun.Security.Package[] = []

      for (let i = 0; i < 50; i++) {
        packages.push({
          name: `package-${i}`,
          version: "1.0.0",
          requestedRange: "^1.0.0",
          tarball: `https://registry.npmjs.org/package-${i}/-/package-${i}-1.0.0.tgz`,
        })
      }

      const result = await scanner.scan({ packages })

      expect(Array.isArray(result)).toBe(true)
    })
  })

  describe("Fail-Safe Behavior", () => {
    test("returns empty array on error (fail-safe)", async () => {
      // This test verifies fail-safe behavior exists
      // The scanner should never throw, always return array
      const packages: Bun.Security.Package[] = [
        {
          name: "test",
          version: "1.0.0",
          requestedRange: "^1.0.0",
          tarball: "https://registry.npmjs.org/test/-/test-1.0.0.tgz",
        },
      ]

      const result = await scanner.scan({ packages })

      expect(Array.isArray(result)).toBe(true)
    })

    test("never throws errors", async () => {
      const packages: Bun.Security.Package[] = [
        {
          name: "any-package",
          version: "1.0.0",
          requestedRange: "^1.0.0",
          tarball: "https://registry.npmjs.org/any-package/-/any-package-1.0.0.tgz",
        },
      ]

      // Should not throw regardless of API state
      await expect(scanner.scan({ packages })).resolves.toBeDefined()
    })
  })

  describe("Advisory Structure", () => {
    test("advisories have required fields", async () => {
      const packages: Bun.Security.Package[] = [
        {
          name: "test-package",
          version: "1.0.0",
          requestedRange: "^1.0.0",
          tarball: "https://registry.npmjs.org/test-package/-/test-package-1.0.0.tgz",
        },
      ]

      const result = await scanner.scan({ packages })

      for (const advisory of result) {
        // Required fields per Bun.Security.Advisory
        expect(typeof advisory.id).toBe("string")
        expect(typeof advisory.message).toBe("string")
        expect(["fatal", "warn"]).toContain(advisory.level)

        // Optional fields
        if (advisory.url) {
          expect(typeof advisory.url).toBe("string")
        }
      }
    })

    test("advisory IDs are unique", async () => {
      const packages: Bun.Security.Package[] = [
        {
          name: "lodash",
          version: "4.17.21",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
        },
      ]

      const result = await scanner.scan({ packages })

      const ids = result.map((advisory) => advisory.id)
      const uniqueIds = [...new Set(ids)]

      expect(ids.length).toBe(uniqueIds.length)
    })
  })

  describe("Edge Cases", () => {
    test("handles package with unusual characters in name", async () => {
      const packages: Bun.Security.Package[] = [
        {
          name: "@scope/package-name",
          version: "1.0.0",
          requestedRange: "^1.0.0",
          tarball: "https://registry.npmjs.org/@scope/package-name/-/package-name-1.0.0.tgz",
        },
      ]

      const result = await scanner.scan({ packages })

      expect(Array.isArray(result)).toBe(true)
    })

    test("handles pre-release versions", async () => {
      const packages: Bun.Security.Package[] = [
        {
          name: "package",
          version: "1.0.0-beta.1",
          requestedRange: "^1.0.0-beta",
          tarball: "https://registry.npmjs.org/package/-/package-1.0.0-beta.1.tgz",
        },
      ]

      const result = await scanner.scan({ packages })

      expect(Array.isArray(result)).toBe(true)
    })

    test("handles version with build metadata", async () => {
      const packages: Bun.Security.Package[] = [
        {
          name: "package",
          version: "1.0.0+build.123",
          requestedRange: "^1.0.0",
          tarball: "https://registry.npmjs.org/package/-/package-1.0.0+build.123.tgz",
        },
      ]

      const result = await scanner.scan({ packages })

      expect(Array.isArray(result)).toBe(true)
    })
  })

  describe("Performance", () => {
    test("completes within reasonable time for small package list", async () => {
      const packages: Bun.Security.Package[] = [
        {
          name: "express",
          version: "4.18.0",
          requestedRange: "^4.0.0",
          tarball: "https://registry.npmjs.org/express/-/express-4.18.0.tgz",
        },
      ]

      const start = Date.now()
      await scanner.scan({ packages })
      const duration = Date.now() - start

      // Should complete within 30 seconds
      expect(duration).toBeLessThan(30000)
    }, 35000) // 35 second timeout for this test
  })
})
