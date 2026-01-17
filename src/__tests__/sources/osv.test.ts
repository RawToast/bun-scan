import { beforeEach, describe, expect, test } from "bun:test"
import { createOSVSource } from "~/sources/osv"
import type { VulnerabilitySource } from "~/sources/types"

describe("OSVSource", () => {
  beforeEach(() => {
    process.env.BUN_SCAN_LOG_LEVEL = "error"
  })

  test("implements VulnerabilitySource interface", () => {
    const source: VulnerabilitySource = createOSVSource({})
    expect(source.name).toBe("osv")
    expect(typeof source.scan).toBe("function")
  })

  test("returns empty array for empty packages", async () => {
    const source = createOSVSource({})
    const result = await source.scan([])
    expect(result).toEqual([])
  })
})
