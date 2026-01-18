/**
 * Structured logging utilities for OSV Scanner
 * Provides consistent, configurable logging with proper levels and context
 *
 * Log level is read ONCE at module load (or factory call) for zero-cost disabled levels.
 * Disabled log functions are NOPs - no runtime checks.
 */

import { ENV } from "./constants.js"

export type LogLevel = "debug" | "info" | "warn" | "error"
export type LogContext = Record<string, unknown>

export type Logger = {
  debug(message: string, context?: LogContext): void
  info(message: string, context?: LogContext): void
  warn(message: string, context?: LogContext): void
  error(message: string, context?: LogContext): void
}

const LEVELS = { debug: 0, info: 1, warn: 2, error: 3 } as const

function parseLogLevel(level?: string): LogLevel | null {
  if (!level) return null
  const normalized = level.toLowerCase()
  return normalized in LEVELS ? (normalized as LogLevel) : null
}

function safeStringify(obj: unknown): string {
  try {
    return JSON.stringify(obj)
  } catch {
    return "[Circular]"
  }
}

function formatMessage(level: LogLevel, message: string, context?: LogContext): string {
  const timestamp = new Date().toISOString()
  const prefix = `[${timestamp}] OSV-${level.toUpperCase()}:`
  const contextStr = context ? ` ${safeStringify(context)}` : ""
  return `${prefix} ${message}${contextStr}`
}

// NOP function for disabled log levels - zero runtime cost
const noop = () => {}

// Real log functions
const realDebug = (message: string, context?: LogContext) =>
  console.debug(formatMessage("debug", message, context))

const realInfo = (message: string, context?: LogContext) =>
  console.info(formatMessage("info", message, context))

const realWarn = (message: string, context?: LogContext) =>
  console.warn(formatMessage("warn", message, context))

const realError = (message: string, context?: LogContext) =>
  console.error(formatMessage("error", message, context))

/**
 * Create a logger with the specified log level.
 * Log level is evaluated once - disabled levels are NOPs with zero runtime cost.
 */
export function createLogger(level?: LogLevel): Logger {
  const minLevel = LEVELS[level ?? parseLogLevel(Bun.env[ENV.LOG_LEVEL]) ?? "info"]

  return {
    debug: minLevel <= LEVELS.debug ? realDebug : noop,
    info: minLevel <= LEVELS.info ? realInfo : noop,
    warn: minLevel <= LEVELS.warn ? realWarn : noop,
    error: realError, // always enabled
  }
}

/** Default logger - reads BUN_SCAN_LOG_LEVEL once at module load */
export const logger = createLogger()
