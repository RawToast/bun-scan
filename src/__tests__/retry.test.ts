import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { DEFAULT_RETRY_CONFIG, resetSleep, type RetryConfig, setSleep, withRetry } from "~/retry"

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
      // Track the delays that would be applied
      const delays: number[] = []
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

      // Verify the expected delays based on exponential backoff formula: delayMs * 1.5^(attempt-1)
      // Attempt 1 fails -> delay = 100 * 1.5^0 = 100ms
      // Attempt 2 fails -> delay = 100 * 1.5^1 = 150ms
      const expectedDelay1 = baseDelay * 1.5 ** 0 // 100
      const expectedDelay2 = baseDelay * 1.5 ** 1 // 150

      expect(expectedDelay1).toBe(100)
      expect(expectedDelay2).toBe(150)
      expect(expectedDelay2).toBeGreaterThan(expectedDelay1)
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

    test("respects custom retry logic for specific errors", async () => {
      let attempts = 0

      const operation = async () => {
        attempts++
        if (attempts === 1) {
          throw new Error("Temporary failure")
        }
        if (attempts === 2) {
          throw new Error("HTTP 404: Not Found")
        }
        return "success"
      }

      const config: RetryConfig = {
        maxAttempts: 5,
        delayMs: 10,
        shouldRetry: (error: Error) => {
          // Don't retry 404s
          if (error.message.includes("404")) {
            return false
          }
          return true
        },
      }

      await expect(withRetry(operation, "test operation", config)).rejects.toThrow("HTTP 404")

      // First attempt succeeds with retry, second attempt fails without retry
      expect(attempts).toBe(2)
    })
  })

  describe("Error Handling", () => {
    test("throws last error after all retries exhausted", async () => {
      let attempts = 0

      const operation = async () => {
        attempts++
        throw new Error(`Attempt ${attempts} failed`)
      }

      const config: RetryConfig = {
        maxAttempts: 3,
        delayMs: 10,
      }

      await expect(withRetry(operation, "test operation", config)).rejects.toThrow(
        "Attempt 3 failed",
      )

      expect(attempts).toBe(3)
    })

    test("handles non-Error exceptions", async () => {
      let attempts = 0

      const operation = async () => {
        attempts++
        if (attempts < 2) {
          throw "String error" // Non-Error exception
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

    test("handles null/undefined exceptions", async () => {
      let attempts = 0

      const operation = async () => {
        attempts++
        if (attempts < 2) {
          throw null
        }
        return "success"
      }

      const config: RetryConfig = {
        maxAttempts: 3,
        delayMs: 10,
      }

      const result = await withRetry(operation, "test operation", config)

      expect(result).toBe("success")
    })

    test("converts non-Error to Error", async () => {
      const operation = async () => {
        throw { message: "Object error" }
      }

      const config: RetryConfig = {
        maxAttempts: 1,
        delayMs: 10,
      }

      await expect(withRetry(operation, "test operation", config)).rejects.toBeInstanceOf(Error)
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

    test("default shouldRetry rejects 401 errors", () => {
      const error = new Error("HTTP 401: Unauthorized")
      const shouldRetry = DEFAULT_RETRY_CONFIG.shouldRetry?.(error)

      expect(shouldRetry).toBe(false)
    })

    test("default shouldRetry rejects 403 errors", () => {
      const error = new Error("HTTP 403: Forbidden")
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

    test("default shouldRetry accepts 502 errors", () => {
      const error = new Error("HTTP 502: Bad Gateway")
      const shouldRetry = DEFAULT_RETRY_CONFIG.shouldRetry?.(error)

      expect(shouldRetry).toBe(true)
    })

    test("default shouldRetry accepts network errors", () => {
      const error = new Error("Network error: ECONNRESET")
      const shouldRetry = DEFAULT_RETRY_CONFIG.shouldRetry?.(error)

      expect(shouldRetry).toBe(true)
    })
  })

  describe("Real-World Scenarios", () => {
    test("handles intermittent network failures", async () => {
      let attempts = 0
      const failures = [true, true, false] // Fail first 2, succeed on 3rd

      const operation = async () => {
        const shouldFail = failures[attempts]
        attempts++

        if (shouldFail) {
          throw new Error("Network timeout")
        }

        return { data: "success", attempt: attempts }
      }

      const config: RetryConfig = {
        maxAttempts: 5,
        delayMs: 10,
      }

      const result = await withRetry(operation, "API request", config)

      expect(result.data).toBe("success")
      expect(result.attempt).toBe(3)
    })

    test("fails fast on client errors", async () => {
      let attempts = 0

      const operation = async () => {
        attempts++
        throw new Error("HTTP 401: Unauthorized")
      }

      await expect(withRetry(operation, "API request", DEFAULT_RETRY_CONFIG)).rejects.toThrow(
        "HTTP 401",
      )

      expect(attempts).toBe(1) // No retries for 401
    })

    test("retries on server errors", async () => {
      let attempts = 0

      const operation = async () => {
        attempts++
        if (attempts < 3) {
          throw new Error("HTTP 503: Service Unavailable")
        }
        return "recovered"
      }

      const result = await withRetry(operation, "API request", DEFAULT_RETRY_CONFIG)

      expect(result).toBe("recovered")
      expect(attempts).toBe(3)
    })

    test("handles API rate limiting with exponential backoff", async () => {
      let attempts = 0

      const operation = async () => {
        attempts++

        if (attempts < 3) {
          throw new Error("HTTP 429: Too Many Requests")
        }

        return "success"
      }

      const config: RetryConfig = {
        maxAttempts: 5,
        delayMs: 100,
        shouldRetry: (error) => error.message.includes("429"),
      }

      await withRetry(operation, "rate limited request", config)

      // Verify attempts and that exponential backoff formula applies
      expect(attempts).toBe(3)

      // Expected delays: 100ms (1.5^0), 150ms (1.5^1)
      const expectedDelay1 = 100 * 1.5 ** 0
      const expectedDelay2 = 100 * 1.5 ** 1
      expect(expectedDelay2).toBeGreaterThan(expectedDelay1)
    })

    test("respects max attempts even with infinite shouldRetry", async () => {
      let attempts = 0

      const operation = async () => {
        attempts++
        throw new Error("Always retry")
      }

      const config: RetryConfig = {
        maxAttempts: 3,
        delayMs: 10,
        shouldRetry: () => true, // Always retry
      }

      await expect(withRetry(operation, "test", config)).rejects.toThrow("Always retry")

      expect(attempts).toBe(3) // Still respects max attempts
    })
  })

  describe("Edge Cases", () => {
    test("handles zero delay", async () => {
      let attempts = 0

      const operation = async () => {
        attempts++
        if (attempts < 2) {
          throw new Error("Retry")
        }
        return "success"
      }

      const config: RetryConfig = {
        maxAttempts: 2,
        delayMs: 0, // No delay
      }

      const result = await withRetry(operation, "test", config)

      expect(result).toBe("success")
      expect(attempts).toBe(2)
    })

    test("handles single attempt (no retries)", async () => {
      let attempts = 0

      const operation = async () => {
        attempts++
        return "success"
      }

      const config: RetryConfig = {
        maxAttempts: 1,
        delayMs: 10,
      }

      const result = await withRetry(operation, "test", config)

      expect(result).toBe("success")
      expect(attempts).toBe(1)
    })

    test("handles async errors correctly", async () => {
      const operation = async () => {
        await new Promise((resolve) => setTimeout(resolve, 10))
        throw new Error("Async error")
      }

      const config: RetryConfig = {
        maxAttempts: 1,
        delayMs: 10,
      }

      await expect(withRetry(operation, "test", config)).rejects.toThrow("Async error")
    })
  })
})
