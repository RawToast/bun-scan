import { describe, expect, test } from "bun:test"
import type { VulnerabilitySource } from "~/sources/types"

describe("VulnerabilitySource", () => {
  test("interface is correctly typed", () => {
    // Type-level test - if this compiles, the interface is correctly defined
    const mockSource: VulnerabilitySource = {
      name: "test",
      async scan(_packages) {
        return []
      },
    }

    expect(mockSource.name).toBe("test")
    expect(typeof mockSource.scan).toBe("function")
  })
})
