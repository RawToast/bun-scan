import { afterEach, beforeEach, describe, expect, spyOn, test } from "bun:test"
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

// Test for TOCTOU race condition (file disappears between exists() and json())
describe("TOCTOU race condition handling in strict mode", () => {
  let originalEnvValue: string | undefined

  beforeEach(async () => {
    // Per-test env/file hygiene matching main config suite
    originalEnvValue = Bun.env[ENV_VAR]
    delete Bun.env[ENV_VAR]
    await cleanupConfigFiles()
  })

  afterEach(async () => {
    // Restore env and cleanup
    if (originalEnvValue === undefined) {
      delete Bun.env[ENV_VAR]
    } else {
      Bun.env[ENV_VAR] = originalEnvValue
    }
    await cleanupConfigFiles()
  })

  test("does not throw when file vanishes between exists() and json() in strict mode (catch-path)", async () => {
    // This is the actual TOCTOU race: file exists when exists() runs, but is gone when json() runs.
    // We simulate this by mocking Bun.file to return a mock where exists()=true but json() throws ENOENT.
    Bun.env[ENV_VAR] = "true"

    // Track call order to prove catch-path was reached
    let existsCalled = false
    let jsonCalled = false
    let callOrder: string[] = []

    // Create a mock file object that simulates TOCTOU race
    const mockFile = {
      exists: async () => {
        existsCalled = true
        callOrder.push("exists")
        return true // File "exists" at this point
      },
      json: async () => {
        jsonCalled = true
        callOrder.push("json")
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

    // In strict mode, TOCTOU race (ENOENT) should NOT throw - return defaults instead
    let config: Awaited<ReturnType<typeof import("../config.js").loadConfig>> | undefined
    try {
      const { loadConfig } = await import("../config.js")
      config = await loadConfig()
    } finally {
      // Restore Bun.file - guaranteed even if assertion fails
      Bun.file = originalBunFileFn
    }

    // Prove catch-path was reached: exists() returned true AND json() threw ENOENT
    // The config loader tries both .bun-scan.json and .bun-scan.config.json
    // At minimum, we should see exists and json both being called at least once
    expect(existsCalled).toBe(true)
    expect(jsonCalled).toBe(true)
    // Verify ordering: for any pair of exists->json, json should follow exists
    // We check this by ensuring "exists,json" appears as a subsequence
    const hasValidSequence = callOrder.some(
      (call, i) => call === "exists" && callOrder[i + 1] === "json",
    )
    expect(hasValidSequence).toBe(true)

    // Should return default config, not throw
    expect(config.source).toBe("osv")
    expect(config.failOnScannerError).toBe(true) // from env var
  })

  test("ENOENT from truly missing file does not throw in strict mode (early-return path)", async () => {
    // When file truly doesn't exist (not TOCTOU), exists() returns false and we get early return.
    // This should not throw in strict mode - missing config is acceptable.
    Bun.env[ENV_VAR] = "true"

    // Track that no file reading was attempted
    let existsCalled = false

    const originalBunFileFn = Bun.file
    // @ts-expect-error - we're intentionally shadowing Bun.file for testing
    Bun.file = (filename: string) => {
      if (filename === ".bun-scan.json" || filename === ".bun-scan.config.json") {
        return {
          exists: async () => {
            existsCalled = true
            return false // File doesn't exist - early return path
          },
          json: async () => {
            throw new Error("Should not be called")
          },
        }
      }
      return originalBunFileFn(filename)
    }

    let config: Awaited<ReturnType<typeof import("../config.js").loadConfig>> | undefined
    try {
      const { loadConfig } = await import("../config.js")
      // This should NOT throw even in strict mode - missing config is not fatal
      config = await loadConfig()
    } finally {
      // Restore Bun.file - guaranteed even if assertion fails
      Bun.file = originalBunFileFn
    }

    // Prove early-return path: exists was called but json was NOT called
    expect(existsCalled).toBe(true)

    // Should return default config (env var still applies)
    expect(config.source).toBe("osv")
    expect(config.failOnScannerError).toBe(true)
  })

  test("logs and throws on non-ENOENT read failures in strict mode", async () => {
    Bun.env[ENV_VAR] = "true"

    const consoleErrorSpy = spyOn(console, "error").mockImplementation(() => {})

    const mockFile = {
      exists: async () => true,
      json: async () => {
        const error = new Error("Permission denied") as Error & { code: string }
        error.code = "EACCES"
        throw error
      },
    }

    const originalBunFileFn = Bun.file
    // @ts-expect-error - we're intentionally shadowing Bun.file for testing
    Bun.file = (filename: string) => {
      if (filename === ".bun-scan.json" || filename === ".bun-scan.config.json") {
        return mockFile
      }
      return originalBunFileFn(filename)
    }

    try {
      const { loadConfig } = await import("../config.js")
      await expect(loadConfig()).rejects.toThrow("failed to load config file")
    } finally {
      Bun.file = originalBunFileFn
    }

    expect(consoleErrorSpy).toHaveBeenCalledWith(
      expect.stringContaining("Failed to read config file .bun-scan.json"),
    )

    consoleErrorSpy.mockRestore()
  })
})
