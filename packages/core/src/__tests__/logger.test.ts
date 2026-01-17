import { describe, expect, spyOn, test } from "bun:test"
import { createLogger, logger } from "~/logger.js"

describe("Logger", () => {
  describe("Log Level Filtering", () => {
    test("logs info messages when log level is info", () => {
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

    test("error is always enabled regardless of level", () => {
      const errorLogger = createLogger("error")
      const spy = spyOn(console, "error")

      errorLogger.error("test error")

      expect(spy).toHaveBeenCalled()

      spy.mockRestore()
    })
  })
})
