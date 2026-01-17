import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { DEFAULT_RETRY_CONFIG, resetSleep, type RetryConfig, setSleep, withRetry } from "~/retry.js"

describe("Retry Logic", () => {
  // Track delays for verification in tests
  let recordedDelays: number[] = []

  beforeEach(() => {
    recordedDelays = []
    // Use instant sleep that records delays for verification
    setSleep(async (ms: number) => {
      recordedDelays.push(ms)
    })
  })

  afterEach(() => {
    resetSleep()
  })

  describe("Basic Retry Functionality", () => {
    test("succeeds on first attempt", async () => {
      let attempts = 0

      const operation = async () => {
        attempts++
        return "success"
      }

      const result = await withRetry(operation, "test operation")

      expect(result).toBe("success")
      expect(attempts).toBe(1)
    })

    test("succeeds on second attempt after one failure", async () => {
      let attempts = 0

      const operation = async () => {
        attempts++
        if (attempts === 1) {
          throw new Error("First attempt failed")
        }
        return "success"
      }

      const config: RetryConfig = {
        maxAttempts: 3,
        delayMs: 10,
      }

      const result = await withRetry(operation, "test operation", config)

      expect(result).toBe("success")
      expect(attempts).toBe(2)
    })

    test("fails after max attempts exhausted", async () => {
      let attempts = 0

      const operation = async () => {
        attempts++
        throw new Error("Always fails")
      }

      const config: RetryConfig = {
        maxAttempts: 2,
        delayMs: 10,
      }

      await expect(withRetry(operation, "test operation", config)).rejects.toThrow("Always fails")

      expect(attempts).toBe(2)
    })

    test("returns correct result after retries", async () => {
      let attempts = 0

      const operation = async () => {
        attempts++
        if (attempts < 3) {
          throw new Error("Not ready yet")
        }
        return { data: "final result", attempts }
      }

      const config: RetryConfig = {
        maxAttempts: 5,
        delayMs: 10,
      }

      const result = await withRetry(operation, "test operation", config)

      expect(result).toEqual({ data: "final result", attempts: 3 })
      expect(attempts).toBe(3)
    })
  })

  describe("Exponential Backoff", () => {
    test("applies exponential backoff between retries", async () => {
      let attempts = 0

      const operation = async () => {
        attempts++
        if (attempts < 3) {
          throw new Error("Retry needed")
        }
        return "success"
      }

      const baseDelay = 100
      const config: RetryConfig = {
        maxAttempts: 3,
        delayMs: baseDelay,
      }

      await withRetry(operation, "test operation", config)

      expect(attempts).toBe(3)

      const expectedDelays = [baseDelay * 1.5 ** 0, baseDelay * 1.5 ** 1]

      expect(recordedDelays).toEqual(expectedDelays)
      expect(recordedDelays[1]).toBeGreaterThan(recordedDelays[0] ?? 0)
    })

    test("calculates correct delay for multiple retries", async () => {
      const baseDelay = 100
      const config: RetryConfig = {
        maxAttempts: 4,
        delayMs: baseDelay,
      }

      let attempts = 0

      const operation = async () => {
        attempts++
        if (attempts < 4) {
          throw new Error("Retry")
        }
        return "success"
      }

      await withRetry(operation, "test operation", config)

      // Verify exponential backoff formula: delayMs * 1.5^(attempt-1)
      // Attempt 1: immediate
      // Attempt 2: after 100ms (1.5^0 = 1)
      // Attempt 3: after 150ms (1.5^1 = 1.5)
      // Attempt 4: after 225ms (1.5^2 = 2.25)
      const expectedDelays = [
        baseDelay * 1.5 ** 0, // 100
        baseDelay * 1.5 ** 1, // 150
        baseDelay * 1.5 ** 2, // 225
      ]

      expect(recordedDelays).toEqual(expectedDelays)
      expect(expectedDelays[0]).toBe(100)
      expect(expectedDelays[1]).toBe(150)
      expect(expectedDelays[2]).toBe(225)

      // Each subsequent delay should be roughly 1.5x the previous
      expect(expectedDelays[1]).toBeGreaterThan(expectedDelays[0] ?? 0)
      expect(expectedDelays[2]).toBeGreaterThan(expectedDelays[1] ?? 0)
    })
  })

  describe("shouldRetry Callback", () => {
    test("stops retrying when shouldRetry returns false", async () => {
      let attempts = 0

      const operation = async () => {
        attempts++
        throw new Error("HTTP 400: Bad Request")
      }

      const config: RetryConfig = {
        maxAttempts: 5,
        delayMs: 10,
        shouldRetry: (error: Error) => {
          return !error.message.includes("400")
        },
      }

      await expect(withRetry(operation, "test operation", config)).rejects.toThrow("HTTP 400")

      // Should fail on first attempt without retry
      expect(attempts).toBe(1)
    })

    test("retries when shouldRetry returns true", async () => {
      let attempts = 0

      const operation = async () => {
        attempts++
        if (attempts < 3) {
          throw new Error("HTTP 500: Internal Server Error")
        }
        return "success"
      }

      const config: RetryConfig = {
        maxAttempts: 5,
        delayMs: 10,
        shouldRetry: (error: Error) => {
          return error.message.includes("500")
        },
      }

      const result = await withRetry(operation, "test operation", config)

      expect(result).toBe("success")
      expect(attempts).toBe(3)
    })

    test("uses default shouldRetry when not provided", async () => {
      let attempts = 0

      const operation = async () => {
        attempts++
        if (attempts < 2) {
          throw new Error("Network error")
        }
        return "success"
      }

      const config: RetryConfig = {
        maxAttempts: 3,
        delayMs: 10,
        // No shouldRetry provided, should retry by default
      }

      const result = await withRetry(operation, "test operation", config)

      expect(result).toBe("success")
      expect(attempts).toBe(2)
    })
  })

  describe("DEFAULT_RETRY_CONFIG", () => {
    test("has correct default values", () => {
      expect(DEFAULT_RETRY_CONFIG.maxAttempts).toBe(3) // MAX_RETRY_ATTEMPTS (2) + 1
      expect(DEFAULT_RETRY_CONFIG.delayMs).toBe(1000)
      expect(DEFAULT_RETRY_CONFIG.shouldRetry).toBeInstanceOf(Function)
    })

    test("default shouldRetry rejects 400 errors", () => {
      const error = new Error("HTTP 400: Bad Request")
      const shouldRetry = DEFAULT_RETRY_CONFIG.shouldRetry?.(error)

      expect(shouldRetry).toBe(false)
    })

    test("default shouldRetry rejects 404 errors", () => {
      const error = new Error("HTTP 404: Not Found")
      const shouldRetry = DEFAULT_RETRY_CONFIG.shouldRetry?.(error)

      expect(shouldRetry).toBe(false)
    })

    test("default shouldRetry accepts 500 errors", () => {
      const error = new Error("HTTP 500: Internal Server Error")
      const shouldRetry = DEFAULT_RETRY_CONFIG.shouldRetry?.(error)

      expect(shouldRetry).toBe(true)
    })

    test("default shouldRetry accepts network errors", () => {
      const error = new Error("Network error: ECONNRESET")
      const shouldRetry = DEFAULT_RETRY_CONFIG.shouldRetry?.(error)

      expect(shouldRetry).toBe(true)
    })
  })
})
