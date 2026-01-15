/**
 * Copyright (c) 2025 maloma7. All rights reserved.
 * SPDX-License-Identifier: MIT
 */

import { beforeEach, describe, expect, spyOn, test } from "bun:test"
import { logger } from "../src/logger.js"

describe("Logger", () => {
  // Store original console methods
  const originalConsole = {
    debug: console.debug,
    info: console.info,
    warn: console.warn,
    error: console.error,
  }

  // Store original log level
  const _originalLogLevel = process.env.OSV_LOG_LEVEL

  beforeEach(() => {
    // Reset log level before each test
    delete process.env.OSV_LOG_LEVEL

    // Reset console methods
    console.debug = originalConsole.debug
    console.info = originalConsole.info
    console.warn = originalConsole.warn
    console.error = originalConsole.error
  })

  describe("Log Level Filtering", () => {
    test("logs info messages when log level is info (default)", () => {
      const spy = spyOn(console, "info")

      logger.info("test message")

      expect(spy).toHaveBeenCalled()
    })

    test("does not log debug messages when log level is info", () => {
      const spy = spyOn(console, "debug")

      logger.debug("debug message")

      expect(spy).not.toHaveBeenCalled()
    })

    test("logs all levels when log level is debug", () => {
      process.env.OSV_LOG_LEVEL = "debug"

      const debugSpy = spyOn(console, "debug")
      const infoSpy = spyOn(console, "info")
      const warnSpy = spyOn(console, "warn")
      const errorSpy = spyOn(console, "error")

      logger.debug("debug")
      logger.info("info")
      logger.warn("warn")
      logger.error("error")

      expect(debugSpy).toHaveBeenCalled()
      expect(infoSpy).toHaveBeenCalled()
      expect(warnSpy).toHaveBeenCalled()
      expect(errorSpy).toHaveBeenCalled()
    })

    test("only logs warn and error when log level is warn", () => {
      process.env.OSV_LOG_LEVEL = "warn"

      const debugSpy = spyOn(console, "debug")
      const infoSpy = spyOn(console, "info")
      const warnSpy = spyOn(console, "warn")
      const errorSpy = spyOn(console, "error")

      logger.debug("debug")
      logger.info("info")
      logger.warn("warn")
      logger.error("error")

      expect(debugSpy).not.toHaveBeenCalled()
      expect(infoSpy).not.toHaveBeenCalled()
      expect(warnSpy).toHaveBeenCalled()
      expect(errorSpy).toHaveBeenCalled()
    })

    test("only logs error when log level is error", () => {
      process.env.OSV_LOG_LEVEL = "error"

      const debugSpy = spyOn(console, "debug")
      const infoSpy = spyOn(console, "info")
      const warnSpy = spyOn(console, "warn")
      const errorSpy = spyOn(console, "error")

      logger.debug("debug")
      logger.info("info")
      logger.warn("warn")
      logger.error("error")

      expect(debugSpy).not.toHaveBeenCalled()
      expect(infoSpy).not.toHaveBeenCalled()
      expect(warnSpy).not.toHaveBeenCalled()
      expect(errorSpy).toHaveBeenCalled()
    })
  })

  describe("Message Formatting", () => {
    test("formats message with timestamp and level prefix", () => {
      const spy = spyOn(console, "info")

      logger.info("test message")

      expect(spy).toHaveBeenCalled()
      const call = spy.mock.calls[0]?.[0] as string

      expect(call).toMatch(/\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\]/)
      expect(call).toContain("OSV-INFO:")
      expect(call).toContain("test message")
    })

    test("includes context object when provided", () => {
      const spy = spyOn(console, "info")

      logger.info("test", { key: "value", count: 42 })

      expect(spy).toHaveBeenCalled()
      const call = spy.mock.calls[0]?.[0] as string

      expect(call).toContain("test")
      expect(call).toContain('"key":"value"')
      expect(call).toContain('"count":42')
    })

    test("handles circular references in context", () => {
      const spy = spyOn(console, "info")

      const circular: Record<string, unknown> = { name: "test" }
      circular.self = circular

      logger.info("circular test", circular)

      expect(spy).toHaveBeenCalled()
      const call = spy.mock.calls[0]?.[0] as string

      expect(call).toContain("[Circular]")
    })

    test("formats different log levels correctly", () => {
      process.env.OSV_LOG_LEVEL = "debug"

      const debugSpy = spyOn(console, "debug")
      const infoSpy = spyOn(console, "info")
      const warnSpy = spyOn(console, "warn")
      const errorSpy = spyOn(console, "error")

      logger.debug("debug")
      logger.info("info")
      logger.warn("warn")
      logger.error("error")

      expect(debugSpy.mock.calls[0]?.[0]).toContain("OSV-DEBUG:")
      expect(infoSpy.mock.calls[0]?.[0]).toContain("OSV-INFO:")
      expect(warnSpy.mock.calls[0]?.[0]).toContain("OSV-WARN:")
      expect(errorSpy.mock.calls[0]?.[0]).toContain("OSV-ERROR:")
    })
  })

  describe("Environment Variable Parsing", () => {
    test("handles uppercase log level", () => {
      process.env.OSV_LOG_LEVEL = "DEBUG"

      const spy = spyOn(console, "debug")
      logger.debug("test")

      expect(spy).toHaveBeenCalled()
    })

    test("handles mixed case log level", () => {
      process.env.OSV_LOG_LEVEL = "WaRn"

      const infoSpy = spyOn(console, "info")
      const warnSpy = spyOn(console, "warn")

      logger.info("info")
      logger.warn("warn")

      expect(infoSpy).not.toHaveBeenCalled()
      expect(warnSpy).toHaveBeenCalled()
    })

    test("falls back to info for invalid log level", () => {
      process.env.OSV_LOG_LEVEL = "invalid"

      const debugSpy = spyOn(console, "debug")
      const infoSpy = spyOn(console, "info")

      logger.debug("debug")
      logger.info("info")

      expect(debugSpy).not.toHaveBeenCalled()
      expect(infoSpy).toHaveBeenCalled()
    })

    test("falls back to info when env var is empty", () => {
      process.env.OSV_LOG_LEVEL = ""

      const debugSpy = spyOn(console, "debug")
      const infoSpy = spyOn(console, "info")

      logger.debug("debug")
      logger.info("info")

      expect(debugSpy).not.toHaveBeenCalled()
      expect(infoSpy).toHaveBeenCalled()
    })
  })

  describe("Context Serialization", () => {
    test("handles primitive values in context", () => {
      const spy = spyOn(console, "info")

      logger.info("test", {
        string: "value",
        number: 42,
        boolean: true,
        null: null,
        undefined: undefined,
      })

      expect(spy).toHaveBeenCalled()
      const call = spy.mock.calls[0]?.[0] as string

      expect(call).toContain('"string":"value"')
      expect(call).toContain('"number":42')
      expect(call).toContain('"boolean":true')
      expect(call).toContain('"null":null')
    })

    test("handles nested objects in context", () => {
      const spy = spyOn(console, "info")

      logger.info("test", {
        nested: {
          deep: {
            value: "test",
          },
        },
      })

      expect(spy).toHaveBeenCalled()
      const call = spy.mock.calls[0]?.[0] as string

      expect(call).toContain('"value":"test"')
    })

    test("handles arrays in context", () => {
      const spy = spyOn(console, "info")

      logger.info("test", {
        array: [1, 2, 3],
        mixedArray: ["string", 42, true],
      })

      expect(spy).toHaveBeenCalled()
      const call = spy.mock.calls[0]?.[0] as string

      expect(call).toContain('"array":[1,2,3]')
      expect(call).toContain('"mixedArray":["string",42,true]')
    })

    test("handles empty context object", () => {
      const spy = spyOn(console, "info")

      logger.info("test", {})

      expect(spy).toHaveBeenCalled()
      const call = spy.mock.calls[0]?.[0] as string

      expect(call).toContain("test {}")
    })

    test("handles no context", () => {
      const spy = spyOn(console, "info")

      logger.info("test")

      expect(spy).toHaveBeenCalled()
      const call = spy.mock.calls[0]?.[0] as string

      expect(call).not.toContain("{")
      expect(call).toContain("test")
    })
  })

  describe("Real-World Usage", () => {
    test("logs OSV scan start", () => {
      const spy = spyOn(console, "info")

      logger.info("Starting OSV scan for 5 packages")

      expect(spy).toHaveBeenCalled()
      const call = spy.mock.calls[0]?.[0] as string

      expect(call).toContain("Starting OSV scan for 5 packages")
    })

    test("logs OSV scan completion with context", () => {
      const spy = spyOn(console, "info")

      logger.info("OSV scan completed", {
        packages: 10,
        vulnerabilities: 3,
        duration: 250,
      })

      expect(spy).toHaveBeenCalled()
      const call = spy.mock.calls[0]?.[0] as string

      expect(call).toContain("OSV scan completed")
      expect(call).toContain('"packages":10')
      expect(call).toContain('"vulnerabilities":3')
    })

    test("logs errors with stack trace in context", () => {
      const spy = spyOn(console, "error")

      const error = new Error("Network failure")
      logger.error("OSV API request failed", {
        error: error.message,
        stack: error.stack,
      })

      expect(spy).toHaveBeenCalled()
      const call = spy.mock.calls[0]?.[0] as string

      expect(call).toContain("OSV API request failed")
      expect(call).toContain("Network failure")
    })

    test("logs warnings for retry attempts", () => {
      process.env.OSV_LOG_LEVEL = "warn"

      const spy = spyOn(console, "warn")

      logger.warn("Request failed, retrying", {
        attempt: 1,
        delay: 1000,
      })

      expect(spy).toHaveBeenCalled()
      const call = spy.mock.calls[0]?.[0] as string

      expect(call).toContain("Request failed, retrying")
      expect(call).toContain('"attempt":1')
      expect(call).toContain('"delay":1000')
    })

    test("logs debug information in verbose mode", () => {
      process.env.OSV_LOG_LEVEL = "debug"

      const spy = spyOn(console, "debug")

      logger.debug("Checking version range", {
        package: "lodash",
        version: "4.17.21",
        range: ">=4.0.0 <5.0.0",
      })

      expect(spy).toHaveBeenCalled()
      const call = spy.mock.calls[0]?.[0] as string

      expect(call).toContain("Checking version range")
      expect(call).toContain('"package":"lodash"')
    })
  })
})
