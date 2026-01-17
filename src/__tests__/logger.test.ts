import { describe, expect, spyOn, test } from "bun:test"
import { createLogger, logger } from "~/logger"

describe("Logger", () => {
  describe("Log Level Filtering", () => {
    test("logs info messages when log level is info (default)", () => {
      const testLogger = createLogger("info")
      const spy = spyOn(console, "info")

      testLogger.info("test message")

      expect(spy).toHaveBeenCalled()
      spy.mockRestore()
    })

    test("does not log debug messages when log level is info", () => {
      const testLogger = createLogger("info")
      const spy = spyOn(console, "debug")

      testLogger.debug("debug message")

      expect(spy).not.toHaveBeenCalled()
      spy.mockRestore()
    })

    test("logs all levels when log level is debug", () => {
      const testLogger = createLogger("debug")
      const debugSpy = spyOn(console, "debug")
      const infoSpy = spyOn(console, "info")
      const warnSpy = spyOn(console, "warn")
      const errorSpy = spyOn(console, "error")

      testLogger.debug("debug")
      testLogger.info("info")
      testLogger.warn("warn")
      testLogger.error("error")

      expect(debugSpy).toHaveBeenCalled()
      expect(infoSpy).toHaveBeenCalled()
      expect(warnSpy).toHaveBeenCalled()
      expect(errorSpy).toHaveBeenCalled()

      debugSpy.mockRestore()
      infoSpy.mockRestore()
      warnSpy.mockRestore()
      errorSpy.mockRestore()
    })

    test("only logs warn and error when log level is warn", () => {
      const testLogger = createLogger("warn")
      const debugSpy = spyOn(console, "debug")
      const infoSpy = spyOn(console, "info")
      const warnSpy = spyOn(console, "warn")
      const errorSpy = spyOn(console, "error")

      testLogger.debug("debug")
      testLogger.info("info")
      testLogger.warn("warn")
      testLogger.error("error")

      expect(debugSpy).not.toHaveBeenCalled()
      expect(infoSpy).not.toHaveBeenCalled()
      expect(warnSpy).toHaveBeenCalled()
      expect(errorSpy).toHaveBeenCalled()

      debugSpy.mockRestore()
      infoSpy.mockRestore()
      warnSpy.mockRestore()
      errorSpy.mockRestore()
    })

    test("only logs error when log level is error", () => {
      const testLogger = createLogger("error")
      const debugSpy = spyOn(console, "debug")
      const infoSpy = spyOn(console, "info")
      const warnSpy = spyOn(console, "warn")
      const errorSpy = spyOn(console, "error")

      testLogger.debug("debug")
      testLogger.info("info")
      testLogger.warn("warn")
      testLogger.error("error")

      expect(debugSpy).not.toHaveBeenCalled()
      expect(infoSpy).not.toHaveBeenCalled()
      expect(warnSpy).not.toHaveBeenCalled()
      expect(errorSpy).toHaveBeenCalled()

      debugSpy.mockRestore()
      infoSpy.mockRestore()
      warnSpy.mockRestore()
      errorSpy.mockRestore()
    })
  })

  describe("Message Formatting", () => {
    test("formats message with timestamp and level prefix", () => {
      const testLogger = createLogger("info")
      const spy = spyOn(console, "info")

      testLogger.info("test message")

      expect(spy).toHaveBeenCalled()
      const call = spy.mock.calls[0]?.[0] as string

      expect(call).toMatch(/\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\]/)
      expect(call).toContain("OSV-INFO:")
      expect(call).toContain("test message")

      spy.mockRestore()
    })

    test("includes context object when provided", () => {
      const testLogger = createLogger("info")
      const spy = spyOn(console, "info")

      testLogger.info("test", { key: "value", count: 42 })

      expect(spy).toHaveBeenCalled()
      const call = spy.mock.calls[0]?.[0] as string

      expect(call).toContain("test")
      expect(call).toContain('"key":"value"')
      expect(call).toContain('"count":42')

      spy.mockRestore()
    })

    test("handles circular references in context", () => {
      const testLogger = createLogger("info")
      const spy = spyOn(console, "info")

      const circular: Record<string, unknown> = { name: "test" }
      circular.self = circular

      testLogger.info("circular test", circular)

      expect(spy).toHaveBeenCalled()
      const call = spy.mock.calls[0]?.[0] as string

      expect(call).toContain("[Circular]")

      spy.mockRestore()
    })

    test("formats different log levels correctly", () => {
      const testLogger = createLogger("debug")
      const debugSpy = spyOn(console, "debug")
      const infoSpy = spyOn(console, "info")
      const warnSpy = spyOn(console, "warn")
      const errorSpy = spyOn(console, "error")

      testLogger.debug("debug")
      testLogger.info("info")
      testLogger.warn("warn")
      testLogger.error("error")

      expect(debugSpy.mock.calls[0]?.[0]).toContain("OSV-DEBUG:")
      expect(infoSpy.mock.calls[0]?.[0]).toContain("OSV-INFO:")
      expect(warnSpy.mock.calls[0]?.[0]).toContain("OSV-WARN:")
      expect(errorSpy.mock.calls[0]?.[0]).toContain("OSV-ERROR:")

      debugSpy.mockRestore()
      infoSpy.mockRestore()
      warnSpy.mockRestore()
      errorSpy.mockRestore()
    })
  })

  describe("Context Serialization", () => {
    test("handles primitive values in context", () => {
      const testLogger = createLogger("info")
      const spy = spyOn(console, "info")

      testLogger.info("test", {
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

      spy.mockRestore()
    })

    test("handles nested objects in context", () => {
      const testLogger = createLogger("info")
      const spy = spyOn(console, "info")

      testLogger.info("test", {
        nested: {
          deep: {
            value: "test",
          },
        },
      })

      expect(spy).toHaveBeenCalled()
      const call = spy.mock.calls[0]?.[0] as string

      expect(call).toContain('"value":"test"')

      spy.mockRestore()
    })

    test("handles arrays in context", () => {
      const testLogger = createLogger("info")
      const spy = spyOn(console, "info")

      testLogger.info("test", {
        array: [1, 2, 3],
        mixedArray: ["string", 42, true],
      })

      expect(spy).toHaveBeenCalled()
      const call = spy.mock.calls[0]?.[0] as string

      expect(call).toContain('"array":[1,2,3]')
      expect(call).toContain('"mixedArray":["string",42,true]')

      spy.mockRestore()
    })

    test("handles empty context object", () => {
      const testLogger = createLogger("info")
      const spy = spyOn(console, "info")

      testLogger.info("test", {})

      expect(spy).toHaveBeenCalled()
      const call = spy.mock.calls[0]?.[0] as string

      expect(call).toContain("test {}")

      spy.mockRestore()
    })

    test("handles no context", () => {
      const testLogger = createLogger("info")
      const spy = spyOn(console, "info")

      testLogger.info("test")

      expect(spy).toHaveBeenCalled()
      const call = spy.mock.calls[0]?.[0] as string

      expect(call).not.toContain("{")
      expect(call).toContain("test")

      spy.mockRestore()
    })
  })

  describe("Default Logger Export", () => {
    test("exports a logger instance", () => {
      expect(logger).toBeDefined()
      expect(typeof logger.debug).toBe("function")
      expect(typeof logger.info).toBe("function")
      expect(typeof logger.warn).toBe("function")
      expect(typeof logger.error).toBe("function")
    })
  })

  describe("Factory Function", () => {
    test("createLogger returns logger with correct interface", () => {
      const testLogger = createLogger("debug")

      expect(typeof testLogger.debug).toBe("function")
      expect(typeof testLogger.info).toBe("function")
      expect(typeof testLogger.warn).toBe("function")
      expect(typeof testLogger.error).toBe("function")
    })

    test("different log levels produce different loggers", () => {
      const debugLogger = createLogger("debug")
      const errorLogger = createLogger("error")

      // Debug logger should have real debug function
      // Error logger should have noop for debug
      expect(debugLogger.debug).not.toBe(errorLogger.debug)
    })

    test("error is always enabled regardless of level", () => {
      const errorLogger = createLogger("error")
      const spy = spyOn(console, "error")

      errorLogger.error("test error")

      expect(spy).toHaveBeenCalled()

      spy.mockRestore()
    })
  })

  describe("Real-World Usage", () => {
    test("logs OSV scan start", () => {
      const testLogger = createLogger("info")
      const spy = spyOn(console, "info")

      testLogger.info("Starting OSV scan for 5 packages")

      expect(spy).toHaveBeenCalled()
      const call = spy.mock.calls[0]?.[0] as string

      expect(call).toContain("Starting OSV scan for 5 packages")

      spy.mockRestore()
    })

    test("logs OSV scan completion with context", () => {
      const testLogger = createLogger("info")
      const spy = spyOn(console, "info")

      testLogger.info("OSV scan completed", {
        packages: 10,
        vulnerabilities: 3,
        duration: 250,
      })

      expect(spy).toHaveBeenCalled()
      const call = spy.mock.calls[0]?.[0] as string

      expect(call).toContain("OSV scan completed")
      expect(call).toContain('"packages":10')
      expect(call).toContain('"vulnerabilities":3')

      spy.mockRestore()
    })

    test("logs errors with stack trace in context", () => {
      const testLogger = createLogger("error")
      const spy = spyOn(console, "error")

      const error = new Error("Network failure")
      testLogger.error("OSV API request failed", {
        error: error.message,
        stack: error.stack,
      })

      expect(spy).toHaveBeenCalled()
      const call = spy.mock.calls[0]?.[0] as string

      expect(call).toContain("OSV API request failed")
      expect(call).toContain("Network failure")

      spy.mockRestore()
    })

    test("logs warnings for retry attempts", () => {
      const testLogger = createLogger("warn")
      const spy = spyOn(console, "warn")

      testLogger.warn("Request failed, retrying", {
        attempt: 1,
        delay: 1000,
      })

      expect(spy).toHaveBeenCalled()
      const call = spy.mock.calls[0]?.[0] as string

      expect(call).toContain("Request failed, retrying")
      expect(call).toContain('"attempt":1')
      expect(call).toContain('"delay":1000')

      spy.mockRestore()
    })

    test("logs debug information in verbose mode", () => {
      const testLogger = createLogger("debug")
      const spy = spyOn(console, "debug")

      testLogger.debug("Checking version range", {
        package: "lodash",
        version: "4.17.21",
        range: ">=4.0.0 <5.0.0",
      })

      expect(spy).toHaveBeenCalled()
      const call = spy.mock.calls[0]?.[0] as string

      expect(call).toContain("Checking version range")
      expect(call).toContain('"package":"lodash"')

      spy.mockRestore()
    })
  })
})
