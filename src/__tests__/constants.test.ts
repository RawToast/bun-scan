import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { ENV, getConfig, HTTP, OSV_API, PERFORMANCE, SECURITY } from "~/constants"

describe("Constants", () => {
  const envKeys = [...Object.values(ENV), "TEST_VAR"]

  const captureEnv = (keys: string[]) => {
    const originalEnv: Record<string, string | undefined> = {}

    for (const key of keys) {
      originalEnv[key] = Bun.env[key]
      delete Bun.env[key]
    }

    return () => {
      for (const key of keys) {
        if (originalEnv[key] === undefined) {
          delete Bun.env[key]
        } else {
          Bun.env[key] = originalEnv[key]
        }
      }
    }
  }

  let restoreEnv: (() => void) | undefined

  beforeEach(() => {
    // Clear test env vars
    restoreEnv = captureEnv(envKeys)
  })

  afterEach(() => {
    // Restore original env values to avoid test pollution
    restoreEnv?.()
    restoreEnv = undefined
  })

  describe("OSV_API Constants", () => {
    test("has correct base URL", () => {
      expect(OSV_API.BASE_URL).toBe("https://api.osv.dev/v1")
    })

    test("has reasonable timeout", () => {
      expect(OSV_API.TIMEOUT_MS).toBe(30000)
      expect(OSV_API.TIMEOUT_MS).toBeGreaterThan(0)
    })

    test("has valid batch size limit", () => {
      expect(OSV_API.MAX_BATCH_SIZE).toBe(1000)
      expect(OSV_API.MAX_BATCH_SIZE).toBeGreaterThan(0)
    })

    test("has retry configuration", () => {
      expect(OSV_API.MAX_RETRY_ATTEMPTS).toBe(2)
      expect(OSV_API.RETRY_DELAY_MS).toBe(1000)
    })

    test("has default ecosystem", () => {
      expect(OSV_API.DEFAULT_ECOSYSTEM).toBe("npm")
    })
  })

  describe("HTTP Constants", () => {
    test("has correct content type", () => {
      expect(HTTP.CONTENT_TYPE).toBe("application/json")
    })

    test("has user agent", () => {
      expect(HTTP.USER_AGENT).toMatch(/bun-osv-scanner/)
    })
  })

  describe("SECURITY Constants", () => {
    test("has CVSS fatal threshold", () => {
      expect(SECURITY.CVSS_FATAL_THRESHOLD).toBe(7.0)
      expect(SECURITY.CVSS_FATAL_THRESHOLD).toBeGreaterThanOrEqual(0)
      expect(SECURITY.CVSS_FATAL_THRESHOLD).toBeLessThanOrEqual(10)
    })

    test("has fatal severities list", () => {
      expect(SECURITY.FATAL_SEVERITIES).toContain("CRITICAL")
      expect(SECURITY.FATAL_SEVERITIES).toContain("HIGH")
      expect(SECURITY.FATAL_SEVERITIES.length).toBe(2)
    })

    test("has max vulnerabilities per package", () => {
      expect(SECURITY.MAX_VULNERABILITIES_PER_PACKAGE).toBe(100)
      expect(SECURITY.MAX_VULNERABILITIES_PER_PACKAGE).toBeGreaterThan(0)
    })

    test("has max description length", () => {
      expect(SECURITY.MAX_DESCRIPTION_LENGTH).toBe(200)
      expect(SECURITY.MAX_DESCRIPTION_LENGTH).toBeGreaterThan(0)
    })
  })

  describe("PERFORMANCE Constants", () => {
    test("enables batch queries by default", () => {
      expect(PERFORMANCE.USE_BATCH_QUERIES).toBe(true)
    })

    test("has max concurrent details limit", () => {
      expect(PERFORMANCE.MAX_CONCURRENT_DETAILS).toBe(10)
      expect(PERFORMANCE.MAX_CONCURRENT_DETAILS).toBeGreaterThan(0)
    })

    test("has max response size", () => {
      expect(PERFORMANCE.MAX_RESPONSE_SIZE).toBe(32 * 1024 * 1024)
      expect(PERFORMANCE.MAX_RESPONSE_SIZE).toBeGreaterThan(0)
    })
  })

  describe("ENV Constants", () => {
    test("has correct environment variable names", () => {
      expect(ENV.LOG_LEVEL).toBe("OSV_LOG_LEVEL")
      expect(ENV.API_BASE_URL).toBe("OSV_API_BASE_URL")
      expect(ENV.TIMEOUT_MS).toBe("OSV_TIMEOUT_MS")
      expect(ENV.DISABLE_BATCH).toBe("OSV_DISABLE_BATCH")
    })
  })

  describe("getConfig Function", () => {
    test("returns default value when env var not set", () => {
      const result = getConfig("TEST_VAR", "default")
      expect(result).toBe("default")
    })

    test("returns env value for string default", () => {
      Bun.env.TEST_VAR = "custom"
      const result = getConfig("TEST_VAR", "default")
      expect(result).toBe("custom")
    })

    test("parses number from env var", () => {
      Bun.env.TEST_VAR = "42"
      const result = getConfig("TEST_VAR", 0)
      expect(result).toBe(42)
    })

    test("returns default for invalid number", () => {
      Bun.env.TEST_VAR = "not-a-number"
      const result = getConfig("TEST_VAR", 10)
      expect(result).toBe(10)
    })

    test("parses boolean from env var", () => {
      Bun.env.TEST_VAR = "true"
      const result = getConfig("TEST_VAR", false)
      expect(result).toBe(true)
    })

    test("parses false from env var", () => {
      Bun.env.TEST_VAR = "false"
      const result = getConfig("TEST_VAR", true)
      expect(result).toBe(false)
    })

    test("handles case-insensitive boolean parsing", () => {
      Bun.env.TEST_VAR = "TRUE"
      const result = getConfig("TEST_VAR", false)
      expect(result).toBe(true) // toLowerCase() is used
    })

    test("uses custom parser when provided", () => {
      Bun.env.TEST_VAR = "100"
      const parser = (val: string) => Number.parseInt(val, 10) * 2
      const result = getConfig("TEST_VAR", 0, parser)
      expect(result).toBe(200)
    })

    test("returns default when custom parser throws", () => {
      Bun.env.TEST_VAR = "invalid"
      const parser = (_val: string) => {
        throw new Error("Parse error")
      }
      const result = getConfig("TEST_VAR", 42, parser)
      expect(result).toBe(42)
    })

    test("handles empty string env var", () => {
      Bun.env.TEST_VAR = ""
      const result = getConfig("TEST_VAR", "default")
      expect(result).toBe("default")
    })

    test("parses negative numbers", () => {
      Bun.env.TEST_VAR = "-42"
      const result = getConfig("TEST_VAR", 0)
      expect(result).toBe(-42)
    })

    test("parses floating point numbers", () => {
      Bun.env.TEST_VAR = "3.14"
      const result = getConfig("TEST_VAR", 0.0)
      expect(result).toBe(3.14)
    })
  })

  describe("Real-World Configuration", () => {
    test("gets API base URL from environment", () => {
      Bun.env.OSV_API_BASE_URL = "https://custom.api.test"
      const result: string = getConfig(ENV.API_BASE_URL, OSV_API.BASE_URL)
      expect(result).toEqual("https://custom.api.test")
    })

    test("gets timeout from environment", () => {
      Bun.env.OSV_TIMEOUT_MS = "60000"
      const result: number = getConfig(ENV.TIMEOUT_MS, OSV_API.TIMEOUT_MS)
      expect(result).toEqual(60000)
    })

    test("gets batch disable flag from environment", () => {
      Bun.env.OSV_DISABLE_BATCH = "true"
      const result = getConfig(ENV.DISABLE_BATCH, false)
      expect(result).toBe(true)
    })

    test("uses defaults when no env vars set", () => {
      const baseUrl = getConfig(ENV.API_BASE_URL, OSV_API.BASE_URL)
      const timeout = getConfig(ENV.TIMEOUT_MS, OSV_API.TIMEOUT_MS)
      const disableBatch = getConfig(ENV.DISABLE_BATCH, false)

      expect(baseUrl).toBe(OSV_API.BASE_URL)
      expect(timeout).toBe(OSV_API.TIMEOUT_MS)
      expect(disableBatch).toBe(false)
    })
  })

  describe("Type Safety", () => {
    test("OSV_API is readonly", () => {
      const constants = OSV_API
      expect(Object.isFrozen(constants)).toBe(false) // Not frozen, but readonly in TS
      expect(constants.BASE_URL).toBeTruthy()
    })

    test("FATAL_SEVERITIES is readonly array", () => {
      const severities = SECURITY.FATAL_SEVERITIES
      expect(Array.isArray(severities)).toBe(true)
      expect(severities.length).toBe(2)
    })
  })

  describe("Validation", () => {
    test("timeout is positive", () => {
      expect(OSV_API.TIMEOUT_MS).toBeGreaterThan(0)
    })

    test("max batch size is reasonable", () => {
      expect(OSV_API.MAX_BATCH_SIZE).toBeGreaterThan(0)
      expect(OSV_API.MAX_BATCH_SIZE).toBeLessThanOrEqual(10000)
    })

    test("retry attempts is non-negative", () => {
      expect(OSV_API.MAX_RETRY_ATTEMPTS).toBeGreaterThanOrEqual(0)
    })

    test("retry delay is positive", () => {
      expect(OSV_API.RETRY_DELAY_MS).toBeGreaterThan(0)
    })

    test("CVSS threshold is in valid range", () => {
      expect(SECURITY.CVSS_FATAL_THRESHOLD).toBeGreaterThanOrEqual(0)
      expect(SECURITY.CVSS_FATAL_THRESHOLD).toBeLessThanOrEqual(10)
    })

    test("max response size is reasonable", () => {
      expect(PERFORMANCE.MAX_RESPONSE_SIZE).toBeGreaterThan(0)
      expect(PERFORMANCE.MAX_RESPONSE_SIZE).toBeLessThan(100 * 1024 * 1024) // Less than 100MB
    })
  })
})
