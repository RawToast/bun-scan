/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

/**
 * Structured logging utilities for OSV Scanner
 * Provides consistent, configurable logging with proper levels and context
 */

import { ENV } from "./constants.js"

export type LogLevel = "debug" | "info" | "warn" | "error"
export type LogContext = Record<string, unknown>

interface Logger {
  debug(message: string, context?: LogContext): void
  info(message: string, context?: LogContext): void
  warn(message: string, context?: LogContext): void
  error(message: string, context?: LogContext): void
}

class OSVLogger implements Logger {
  private readonly levels = { debug: 0, info: 1, warn: 2, error: 3 }

  private parseLogLevel(level?: string): LogLevel | null {
    if (!level) return null
    const normalized = level.toLowerCase()
    return ["debug", "info", "warn", "error"].includes(normalized) ? (normalized as LogLevel) : null
  }

  private get minLevel(): LogLevel {
    return this.parseLogLevel(process.env[ENV.LOG_LEVEL]) || "info"
  }

  private shouldLog(level: LogLevel): boolean {
    return this.levels[level] >= this.levels[this.minLevel]
  }

  private safeStringify(obj: unknown): string {
    try {
      return JSON.stringify(obj)
    } catch {
      return "[Circular]"
    }
  }

  private formatMessage(level: LogLevel, message: string, context?: LogContext): string {
    const timestamp = new Date().toISOString()
    const prefix = `[${timestamp}] OSV-${level.toUpperCase()}:`
    const contextStr = context ? ` ${this.safeStringify(context)}` : ""
    return `${prefix} ${message}${contextStr}`
  }

  debug(message: string, context?: LogContext): void {
    if (this.shouldLog("debug")) {
      console.debug(this.formatMessage("debug", message, context))
    }
  }

  info(message: string, context?: LogContext): void {
    if (this.shouldLog("info")) {
      console.info(this.formatMessage("info", message, context))
    }
  }

  warn(message: string, context?: LogContext): void {
    if (this.shouldLog("warn")) {
      console.warn(this.formatMessage("warn", message, context))
    }
  }

  error(message: string, context?: LogContext): void {
    if (this.shouldLog("error")) {
      console.error(this.formatMessage("error", message, context))
    }
  }
}

export const logger = new OSVLogger()
