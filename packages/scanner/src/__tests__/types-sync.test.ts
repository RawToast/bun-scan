import { describe, expect, test } from "bun:test"
import * as scannerExports from "../index.js"

/**
 * This test ensures the hand-written types/index.d.ts stays in sync
 * with the actual exports from src/index.ts
 *
 * If this test fails, update types/index.d.ts to match the new exports
 */
describe("Types Sync", () => {
  // List of all exports that should be in types/index.d.ts
  const expectedExports = [
    // Core values
    "DEFAULT_SOURCE",
    "DEFAULT_RETRY_CONFIG",
    "logger",
    "scanner",

    // Core functions
    "loadConfig",
    "compileIgnoreConfig",
    "shouldIgnoreVulnerability",
    "createLogger",
    "withRetry",

    // Schemas
    "ConfigSchema",
    "IgnoreConfigSchema",

    // Source factories
    "createOSVSource",
    "createNpmSource",
    "createSource",
    "createSources",
    "createMultiSourceScanner",
  ]

  test("all expected exports exist in scanner module", () => {
    const actualExports = Object.keys(scannerExports)

    for (const exportName of expectedExports) {
      expect(actualExports).toContain(exportName)
    }
  })

  test("no unexpected exports in scanner module", () => {
    const actualExports = Object.keys(scannerExports)

    // These are the only exports we expect
    // If new exports are added, add them to expectedExports AND types/index.d.ts
    for (const exportName of actualExports) {
      expect(expectedExports).toContain(exportName)
    }
  })

  test("scanner has correct interface", () => {
    expect(scannerExports.scanner).toBeDefined()
    expect(scannerExports.scanner.version).toBe("1")
    expect(typeof scannerExports.scanner.scan).toBe("function")
  })

  test("factory functions are callable", () => {
    expect(typeof scannerExports.createOSVSource).toBe("function")
    expect(typeof scannerExports.createNpmSource).toBe("function")
    expect(typeof scannerExports.createSource).toBe("function")
    expect(typeof scannerExports.createSources).toBe("function")
    expect(typeof scannerExports.createMultiSourceScanner).toBe("function")
  })

  test("config functions are callable", () => {
    expect(typeof scannerExports.loadConfig).toBe("function")
    expect(typeof scannerExports.compileIgnoreConfig).toBe("function")
    expect(typeof scannerExports.shouldIgnoreVulnerability).toBe("function")
  })

  test("logger is properly exported", () => {
    expect(scannerExports.logger).toBeDefined()
    expect(typeof scannerExports.logger.debug).toBe("function")
    expect(typeof scannerExports.logger.info).toBe("function")
    expect(typeof scannerExports.logger.warn).toBe("function")
    expect(typeof scannerExports.logger.error).toBe("function")
  })
})
