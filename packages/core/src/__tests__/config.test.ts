import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { loadConfig } from "../config.js"

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
  const files = [".bun-scan.json", ".bun-scan.config.json"]
  for (const file of files) {
    const f = Bun.file(file)
    if (await f.exists()) {
      await Bun.write(file, "") // Clear file
      const { unlink } = await import("node:fs/promises")
      await unlink(file)
    }
  }
}

describe("Config", () => {
  beforeEach(async () => {
    await cleanupConfigFiles()
  })

  afterEach(async () => {
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
    await writeConfigFile({ failOnScannerError: false })
    process.env.BUN_SCAN_FAIL_ON_SCANNER_ERROR = "true"
    try {
      const config = await loadConfig()
      expect(config.failOnScannerError).toBe(true)
    } finally {
      delete process.env.BUN_SCAN_FAIL_ON_SCANNER_ERROR
    }
  })

  test("env var false overrides config file true for failOnScannerError", async () => {
    await writeConfigFile({ failOnScannerError: true })
    process.env.BUN_SCAN_FAIL_ON_SCANNER_ERROR = "false"
    try {
      const config = await loadConfig()
      expect(config.failOnScannerError).toBe(false)
    } finally {
      delete process.env.BUN_SCAN_FAIL_ON_SCANNER_ERROR
    }
  })

  test("defaults to false when no config file exists", async () => {
    const config = await loadConfig()
    expect(config.failOnScannerError).toBe(false)
  })
})

describe("failOnScannerError strict config loading", () => {
  test("throws on malformed config when env var is true", async () => {
    await Bun.write(".bun-scan.json", "{ invalid json")
    process.env.BUN_SCAN_FAIL_ON_SCANNER_ERROR = "true"
    try {
      await expect(loadConfig()).rejects.toThrow()
    } finally {
      delete process.env.BUN_SCAN_FAIL_ON_SCANNER_ERROR
    }
  })

  test("does not throw on malformed config when env var is not set", async () => {
    await Bun.write(".bun-scan.json", "{ invalid json")
    const config = await loadConfig()
    expect(config.source).toBe("osv")
  })

  test("does not throw on missing config when env var is true", async () => {
    process.env.BUN_SCAN_FAIL_ON_SCANNER_ERROR = "true"
    try {
      const config = await loadConfig()
      expect(config.failOnScannerError).toBe(true)
    } finally {
      delete process.env.BUN_SCAN_FAIL_ON_SCANNER_ERROR
    }
  })
})
})
