import { describe, expect, test } from "bun:test"
import { createSource, createSources } from "../sources/factory.js"

describe("createSource", () => {
  const emptyConfig = {}

  test("creates OSV source for 'osv'", () => {
    const source = createSource("osv", emptyConfig)
    expect(source.name).toBe("osv")
    expect(typeof source.scan).toBe("function")
  })

  test("creates npm source for 'npm'", () => {
    const source = createSource("npm", emptyConfig)
    expect(source.name).toBe("npm")
    expect(typeof source.scan).toBe("function")
  })

  test("throws for invalid source type", () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => createSource("invalid" as any, emptyConfig)).toThrow()
  })
})

describe("createSources", () => {
  const emptyConfig = {}

  test("returns single source for 'osv'", () => {
    const sources = createSources("osv", emptyConfig)
    expect(sources).toHaveLength(1)
    expect(sources[0]?.name).toBe("osv")
  })

  test("returns single source for 'npm'", () => {
    const sources = createSources("npm", emptyConfig)
    expect(sources).toHaveLength(1)
    expect(sources[0]?.name).toBe("npm")
  })

  test("returns both sources for 'both'", () => {
    const sources = createSources("both", emptyConfig)
    expect(sources).toHaveLength(2)
    expect(sources.map((s) => s.name).sort()).toEqual(["npm", "osv"])
  })
})
