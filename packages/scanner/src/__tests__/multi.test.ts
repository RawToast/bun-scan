import { describe, expect, test } from "bun:test"
import { createMultiSourceScanner } from "~/sources/multi"
import type { VulnerabilitySource } from "@repo/core"

const makeAdvisory = (
  overrides: Partial<Bun.Security.Advisory> & { id: string; package: string },
): Bun.Security.Advisory => ({
  id: overrides.id,
  message: overrides.message ?? overrides.id,
  level: overrides.level ?? "warn",
  package: overrides.package,
  url: overrides.url ?? null,
  description: overrides.description ?? null,
  aliases: overrides.aliases ?? [],
})

const makePackage = (name: string, version: string): Bun.Security.Package => ({
  name,
  version,
  tarball: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
  requestedRange: "*",
})

describe("MultiSourceScanner", () => {
  test("runs single source and returns results", async () => {
    const mockSource: VulnerabilitySource = {
      name: "mock",
      async scan() {
        return [makeAdvisory({ id: "CVE-1", package: "test-pkg" })]
      },
    }

    const scanner = createMultiSourceScanner([mockSource])
    const results = await scanner.scan([makePackage("test-pkg", "1.0.0")])

    expect(results).toHaveLength(1)
    expect(results[0]?.id).toBe("CVE-1")
  })

  test("deduplicates results when ids or aliases overlap", async () => {
    const source1: VulnerabilitySource = {
      name: "source1",
      async scan() {
        return [
          makeAdvisory({ id: "GHSA-aaaa-bbbb-cccc", aliases: ["CVE-1"], package: "pkg" }),
          makeAdvisory({ id: "CVE-2", level: "fatal", package: "pkg" }),
        ]
      },
    }

    const source2: VulnerabilitySource = {
      name: "source2",
      async scan() {
        return [
          makeAdvisory({ id: "CVE-1", level: "fatal", package: "pkg" }),
          makeAdvisory({ id: "CVE-3", package: "pkg" }),
        ]
      },
    }

    const scanner = createMultiSourceScanner([source1, source2])
    const results = await scanner.scan([makePackage("pkg", "1.0.0")])

    // Should have 3 unique vulnerabilities (CVE-1/GHSA deduplicated)
    expect(results).toHaveLength(3)

    // CVE-1/GHSA-aaaa should take the highest severity (fatal from source2)
    const cve1 = results.find((r) => r.id === "CVE-1" || r.aliases?.includes("CVE-1"))
    expect(cve1?.level).toBe("fatal")
  })

  test("queries sources in parallel", async () => {
    let slowDone = false
    let fastDone = false

    const slowSource: VulnerabilitySource = {
      name: "slow",
      async scan() {
        await Bun.sleep(50)
        slowDone = true
        return []
      },
    }

    const fastSource: VulnerabilitySource = {
      name: "fast",
      async scan() {
        fastDone = true
        return []
      },
    }

    const scanner = createMultiSourceScanner([slowSource, fastSource])
    await scanner.scan([])

    expect(fastDone).toBe(true)
    expect(slowDone).toBe(true)
  })

  test("throws if no sources provided", () => {
    expect(() => createMultiSourceScanner([])).toThrow()
  })

  test("handles source failures gracefully", async () => {
    const failingSource: VulnerabilitySource = {
      name: "failing",
      async scan() {
        throw new Error("API error")
      },
    }

    const workingSource: VulnerabilitySource = {
      name: "working",
      async scan() {
        return [makeAdvisory({ id: "CVE-1", package: "pkg" })]
      },
    }

    const scanner = createMultiSourceScanner([failingSource, workingSource])
    const results = await scanner.scan([makePackage("pkg", "1.0.0")])

    // Should still get results from working source
    expect(results).toHaveLength(1)
  })
})
