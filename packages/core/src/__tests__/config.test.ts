import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { loadConfig } from "../config.js"

const ENV_VAR = "BUN_SCAN_FAIL_ON_SCANNER_ERROR"

/**
 * Helper to write a config file for testing
 */
async function writeConfigFile(
  content: Record<string, unknown>,
  filename = ".bun-scan.json",
): Promise<void> {
  await Bun.write(filename, JSON.stringify(content))
}

/**
 * Helper to clean up config files after tests
 */
async function cleanupConfigFiles(): Promise<void> {
  const files = [".bun-scan.json", ".bun-scan.config.json", ".bun-scan-toctou-test.json"]
  for (const file of files) {
    const f = Bun.file(file)
    if (await f.exists()) {
      const { unlink } = await import("node:fs/promises")
      await unlink(file)
    }
  }
}

describe("Config", () => {
  let originalEnvValue: string | undefined

  beforeEach(async () => {
    // Snapshot the original env value for test isolation
    originalEnvValue = Bun.env[ENV_VAR]
    delete Bun.env[ENV_VAR]
    // Ensure filesystem isolation - remove any ambient config files
    await cleanupConfigFiles()
  })

  afterEach(async () => {
    // Restore the original env value instead of just deleting
    if (originalEnvValue === undefined) {
      delete Bun.env[ENV_VAR]
    } else {
      Bun.env[ENV_VAR] = originalEnvValue
    }
    await cleanupConfigFiles()
  })

  describe("source configuration", () => {
    test("defaults to osv when source not specified", async () => {
      await writeConfigFile({})
      const config = await loadConfig()
      expect(config.source).toBe("osv")
    })

    test("accepts valid source values", async () => {
      for (const source of ["osv", "npm", "both"] as const) {
        await writeConfigFile({ source })
        const config = await loadConfig()
        expect(config.source).toBe(source)
      }
    })

    test("falls back to default on invalid source while keeping ignore rules", async () => {
      await writeConfigFile({ source: "invalid", ignore: ["CVE-2024-1234"] })
      const config = await loadConfig()
      expect(config.source).toBe("osv")
      expect(config.ignore).toEqual(["CVE-2024-1234"])
    })

    test("returns ignore config without source field", async () => {
      await writeConfigFile({ source: "npm", ignore: ["CVE-2024-1234"] })
      const { ignore } = await loadConfig()
      expect(ignore).toEqual(["CVE-2024-1234"])
    })
  })

  describe("failOnScannerError configuration", () => {
    test("defaults to false when not specified", async () => {
      await writeConfigFile({})
      const config = await loadConfig()
      expect(config.failOnScannerError).toBe(false)
    })

    test("reads failOnScannerError from config file", async () => {
      await writeConfigFile({ failOnScannerError: true })
      const config = await loadConfig()
      expect(config.failOnScannerError).toBe(true)
    })

    test("env var overrides config file for failOnScannerError", async () => {
      await writeConfigFile({ failOnScannerError: true })
      Bun.env[ENV_VAR] = "false"
      const config = await loadConfig()
      expect(config.failOnScannerError).toBe(false)
    })

    test("env var true overrides config file false for failOnScannerError", async () => {
      await writeConfigFile({ failOnScannerError: false })
      Bun.env[ENV_VAR] = "true"
      const config = await loadConfig()
      expect(config.failOnScannerError).toBe(true)
    })

    test("defaults to false when no config file exists", async () => {
      const config = await loadConfig()
      expect(config.failOnScannerError).toBe(false)
    })

    test("env var is used when no config file exists", async () => {
      Bun.env[ENV_VAR] = "true"
      const config = await loadConfig()
      expect(config.failOnScannerError).toBe(true)
    })

    test("invalid env var value is treated as unset", async () => {
      Bun.env[ENV_VAR] = "wat"
      const config = await loadConfig()
      expect(config.failOnScannerError).toBe(false)
    })
  })

  describe("failOnScannerError strict config loading", () => {
    test("throws on malformed config when env var is true", async () => {
      await Bun.write(".bun-scan.json", "{ invalid json")
      Bun.env[ENV_VAR] = "true"
      await expect(loadConfig()).rejects.toThrow()
    })

    test("does not throw on malformed config when env var is not set", async () => {
      await Bun.write(".bun-scan.json", "{ invalid json")
      const config = await loadConfig()
      expect(config.source).toBe("osv")
    })

    test("does not throw on missing config when env var is true", async () => {
      Bun.env[ENV_VAR] = "true"
      const config = await loadConfig()
      expect(config.failOnScannerError).toBe(true)
    })
  })
})

// CR6: Test for TOCTOU race condition (file disappears between exists() and json())
describe("CR6 TOCTOU race condition", () => {
  const originalEnvValue = Bun.env[ENV_VAR]

  // Track if we're in a test that mocked Bun.file
  let mockRestore: (() => void) | null = null

  afterEach(async () => {
    // Restore Bun.file if we mocked it
    if (mockRestore) {
      mockRestore()
      mockRestore = null
    }
    // Restore env and cleanup
    if (originalEnvValue === undefined) {
      delete Bun.env[ENV_VAR]
    } else {
      Bun.env[ENV_VAR] = originalEnvValue
    }
    await cleanupConfigFiles()
  })

  test("does not throw when file vanishes between exists() and json() in strict mode", async () => {
    // This is the actual TOCTOU race: file exists when exists() runs, but is gone when json() runs.
    // We simulate this by mocking Bun.file to return a mock where exists()=true but json() throws ENOENT.
    await cleanupConfigFiles()
    Bun.env[ENV_VAR] = "true"

    // Create a mock file object that simulates TOCTOU race
    const mockFile = {
      exists: async () => true, // File "exists" at this point
      json: async () => {
        // File "disappeared" by the time we try to read it - simulate ENOENT
        const error = new Error("No such file or directory") as Error & { code: string }
        error.code = "ENOENT"
        throw error
      },
    }

    // Override Bun.file to return our mock for the config filename
    const originalBunFileFn = Bun.file
    // @ts-expect-error - we're intentionally shadowing Bun.file for testing
    Bun.file = (filename: string) => {
      if (filename === ".bun-scan.json" || filename === ".bun-scan.config.json") {
        return mockFile
      }
      return originalBunFileFn(filename)
    }

    // Store restore function
    mockRestore = () => {
      Bun.file = originalBunFileFn
    }

    // In strict mode, TOCTOU race (ENOENT) should NOT throw - return defaults instead
    const { loadConfig } = await import("../config.js")
    const config = await loadConfig()

    // Should return default config, not throw
    expect(config.source).toBe("osv")
    expect(config.failOnScannerError).toBe(true) // from env var
  })

  test("still throws on parse errors in strict mode", async () => {
    // This tests that non-ENOENT errors DO throw in strict mode
    await Bun.write(".bun-scan.json", "{ invalid json }")
    Bun.env[ENV_VAR] = "true"

    const { loadConfig } = await import("../config.js")
    await expect(loadConfig()).rejects.toThrow()
  })

  test("ENOENT from truly missing file does not throw in strict mode", async () => {
    // When file truly doesn't exist (not TOCTOU), exists() returns false and we get early return.
    // This should not throw in strict mode - missing config is acceptable.
    await cleanupConfigFiles()
    Bun.env[ENV_VAR] = "true"

    const { loadConfig } = await import("../config.js")
    // This should NOT throw even in strict mode - missing config is not fatal
    const config = await loadConfig()
    expect(config.source).toBe("osv")
    expect(config.failOnScannerError).toBe(true)
  })
})
