import { OSV_API } from "./constants.js"
import { logger } from "./logger.js"

/**
 * Default sleep implementation using setTimeout
 */
const defaultSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms))

/**
 * Configurable sleep function for testing
 * Can be replaced with a no-op for fast tests
 */
export let sleep = defaultSleep

/**
 * Override the sleep function (for testing)
 */
export function setSleep(fn: (ms: number) => Promise<void>): void {
  sleep = fn
}

/**
 * Reset the sleep function to default
 */
export function resetSleep(): void {
  sleep = defaultSleep
}

/**
 * Retry configuration for network operations
 */
export interface RetryConfig {
  maxAttempts: number
  delayMs: number
  shouldRetry?: (error: Error) => boolean
}

/**
 * Default retry configuration
 */
export const DEFAULT_RETRY_CONFIG: RetryConfig = {
  maxAttempts: OSV_API.MAX_RETRY_ATTEMPTS + 1,
  delayMs: OSV_API.RETRY_DELAY_MS,
  shouldRetry: (error: Error) => {
    // Don't retry on 4xx client errors (except rate limiting)
    if (
      error.message.includes("400") ||
      error.message.includes("401") ||
      error.message.includes("403")
    ) {
      return false
    }
    if (error.message.includes("404")) {
      return false
    }
    // Retry on 5xx server errors and network issues
    return true
  },
}

/**
 * Execute an operation with retry logic
 * Provides exponential backoff and configurable retry conditions
 */
export async function withRetry<T>(
  operation: () => Promise<T>,
  operationName: string,
  config: RetryConfig = DEFAULT_RETRY_CONFIG,
): Promise<T> {
  let lastError: Error = new Error("Unknown error")

  for (let attempt = 1; attempt <= config.maxAttempts; attempt++) {
    try {
      const result = await operation()

      if (attempt > 1) {
        logger.info(`${operationName} succeeded on attempt ${attempt}`)
      }

      return result
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error))

      const isLastAttempt = attempt === config.maxAttempts
      const shouldRetry = config.shouldRetry?.(lastError) ?? true

      if (isLastAttempt || !shouldRetry) {
        logger.error(`${operationName} failed after ${attempt} attempts`, {
          error: lastError.message,
          attempts: attempt,
        })
        break
      }

      const delay = config.delayMs * 1.5 ** (attempt - 1) // Exponential backoff
      logger.warn(`${operationName} attempt ${attempt} failed, retrying in ${delay}ms`, {
        error: lastError.message,
        nextDelay: delay,
      })

      await sleep(delay)
    }
  }

  throw lastError
}
