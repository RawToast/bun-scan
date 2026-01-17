# Multi-Source Scanner Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make bun-scan configurable to use OSV.dev, npm Registry, or both vulnerability sources.

**Architecture:** Extract a common `VulnerabilitySource` interface, move existing OSV implementation into `src/sources/osv/`, adapt npm scanner into `src/sources/npm/`, and create a source factory that selects based on config. Multi-source mode deduplicates advisories per package using IDs and aliases, and logging is standardized via `BUN_SCAN_LOG_LEVEL`. The config file (`.bun-scan.json`) gains a `source` field validated against an updated JSON schema.

**Tech Stack:** TypeScript, Zod for runtime validation, Bun APIs

---

## Task 1: Update JSON Schema with Source Field

**Files:**

- Modify: `schema/bun-scan.schema.json`

**Step 1: Add source property to schema**

Add after line 11 (after `$schema` property):

```json
"source": {
  "type": "string",
  "enum": ["osv", "npm", "both"],
  "default": "osv",
  "description": "Vulnerability data source: 'osv' (OSV.dev), 'npm' (npm Registry), or 'both' (query both and deduplicate)"
}
```

**Step 2: Update schema title/description and ID patterns**

Change title from "OSV Ignore Configuration" to "Bun-Scan Configuration" and update description to reflect multi-source support.

Relax vulnerability ID patterns to allow npm numeric IDs while keeping CVE/GHSA/etc prefixes. Update both `ignore.items.pattern` and `packages.*.vulnerabilities.items.pattern` to:

```json
"pattern": "^(CVE-|GHSA-|PYSEC-|GO-|RUSTSEC-|\\d).+$"
```

**Step 3: Add example with source field**

Add to examples array:

```json
{
  "source": "npm",
  "ignore": ["GHSA-xxxx-xxxx-xxxx"]
}
```

**Step 4: Commit**

```bash
git add schema/bun-scan.schema.json
git commit -m "feat(schema): add source field for multi-source scanning"
```

---

## Task 2: Create VulnerabilitySource Interface

**Files:**

- Create: `src/sources/types.ts`
- Test: `src/__tests__/sources/types.test.ts`

**Step 1: Write the interface test**

```typescript
import { describe, expect, test } from "bun:test"
import type { VulnerabilitySource } from "~/sources/types"

describe("VulnerabilitySource", () => {
  test("interface is correctly typed", () => {
    // Type-level test - if this compiles, the interface is correctly defined
    const mockSource: VulnerabilitySource = {
      name: "test",
      async scan(packages) {
        return []
      },
    }

    expect(mockSource.name).toBe("test")
    expect(typeof mockSource.scan).toBe("function")
  })
})
```

**Step 2: Run test to verify it fails**

Run: `bun test src/__tests__/sources/types.test.ts`
Expected: FAIL with module not found

**Step 3: Create the types file**

```typescript
/**
 * Common interface for vulnerability data sources
 * Abstracts the differences between OSV.dev and npm Registry APIs
 */
export interface VulnerabilitySource {
  /** Source identifier for logging */
  readonly name: string

  /**
   * Scan packages for vulnerabilities
   * Each source implements its own API logic internally
   */
  scan(packages: Bun.Security.Package[]): Promise<Bun.Security.Advisory[]>
}

/** Supported vulnerability source identifiers */
export type SourceType = "osv" | "npm" | "both"

/** Default source when not specified in config */
export const DEFAULT_SOURCE: SourceType = "osv"
```

**Step 4: Run test to verify it passes**

Run: `bun test src/__tests__/sources/types.test.ts`
Expected: PASS

**Step 5: Commit**

```bash
git add src/sources/types.ts src/__tests__/sources/types.test.ts
git commit -m "feat(sources): add VulnerabilitySource interface"
```

---

## Task 3: Update Config to Support Source Field

**Files:**

- Modify: `src/config.ts`
- Modify: `src/__tests__/config.test.ts`

**Step 1: Write failing test for source field**

Add to existing config tests:

```typescript
describe("source configuration", () => {
  test("defaults to osv when source not specified", async () => {
    await writeConfigFile({})
    const config = await loadConfig()
    expect(config.source).toBe("osv")
  })

  test("accepts valid source values", async () => {
    for (const source of ["osv", "npm", "both"] as const) {
      await writeConfigFile({ source })
      const config = await loadConfig()
      expect(config.source).toBe(source)
    }
  })

  test("falls back to default on invalid source while keeping ignore rules", async () => {
    await writeConfigFile({ source: "invalid", ignore: ["CVE-2024-1234"] })
    const config = await loadConfig()
    expect(config.source).toBe("osv")
    expect(config.ignore).toEqual(["CVE-2024-1234"])
  })
})
```

**Step 2: Run test to verify it fails**

Run: `bun test src/__tests__/config.test.ts -t "source configuration"`
Expected: FAIL

**Step 3: Update config schema to include source with safe fallback**

In `src/config.ts`, update the schema to avoid dropping the entire config on invalid source values:

```typescript
import type { SourceType } from "./sources/types.js"
import { DEFAULT_SOURCE } from "./sources/types.js"

// Add to IgnoreConfigSchema
export const ConfigSchema = z.object({
  /** Vulnerability data source */
  source: z.enum(["osv", "npm", "both"]).catch(DEFAULT_SOURCE).optional(),
  /** Vulnerability IDs to ignore globally */
  ignore: z.array(z.string()).optional(),
  /** Package-specific ignore rules */
  packages: z.record(z.string(), IgnorePackageRuleSchema).optional(),
})

export type Config = z.infer<typeof ConfigSchema>
```

**Step 4: Update loadConfig to return full config with source**

Rename `loadIgnoreConfig` to `loadConfig` (keep old name as alias for backwards compat):

```typescript
export async function loadConfig(): Promise<Config> {
  for (const filename of CONFIG_FILES) {
    const config = await tryLoadConfigFile(filename)
    if (config) {
      return { source: DEFAULT_SOURCE, ...config }
    }
  }
  return { source: DEFAULT_SOURCE }
}

// Backwards compatibility
export const loadIgnoreConfig = loadConfig
```

**Step 5: Run test to verify it passes**

Run: `bun test src/__tests__/config.test.ts -t "source configuration"`
Expected: PASS

**Step 6: Run full test suite**

Run: `bun test`
Expected: All tests pass

**Step 7: Commit**

```bash
git add src/config.ts src/__tests__/config.test.ts
git commit -m "feat(config): add source field to configuration"
```

---

## Task 3A: Update Shared Log Level Env Var

**Files:**

- Modify: `src/constants.ts`
- Modify: `src/logger.ts`
- Modify: `src/__tests__/constants.test.ts`
- Modify: `src/__tests__/setup.ts`
- Modify: `src/cli.ts`
- Modify: `README.md`

**Step 1: Update constants test to expect BUN_SCAN_LOG_LEVEL**

Add/replace test in `src/__tests__/constants.test.ts`:

```typescript
test("uses BUN_SCAN_LOG_LEVEL env var", () => {
  expect(ENV.LOG_LEVEL).toBe("BUN_SCAN_LOG_LEVEL")
})
```

**Step 2: Run test to verify it fails**

Run: `bun test src/__tests__/constants.test.ts -t "BUN_SCAN_LOG_LEVEL"`
Expected: FAIL

**Step 3: Update log level env var and logger comments**

- In `src/constants.ts`, set `ENV.LOG_LEVEL` to `"BUN_SCAN_LOG_LEVEL"`.
- In `src/logger.ts`, update comments/usage strings to reference `BUN_SCAN_LOG_LEVEL` and note it is shared for all sources.

**Step 4: Update CLI usage text**

Update `src/cli.ts` usage output to list `BUN_SCAN_LOG_LEVEL` (keep OSV-specific env vars like `OSV_TIMEOUT_MS` unchanged).

**Step 5: Update README env var references**

Replace `OSV_LOG_LEVEL` with `BUN_SCAN_LOG_LEVEL` in the environment variables section and examples.

**Step 6: Run tests to verify**

Run: `bun test src/__tests__/constants.test.ts`
Expected: PASS

**Step 7: Commit**

```bash
git add src/constants.ts src/logger.ts src/__tests__/constants.test.ts src/__tests__/setup.ts src/cli.ts README.md
git commit -m "chore(logging): switch to BUN_SCAN_LOG_LEVEL"
```

---

## Task 4: Extract OSV Implementation to sources/osv/

**Files:**

- Create: `src/sources/osv/index.ts`
- Create: `src/sources/osv/client.ts` (move from `src/client.ts`)
- Create: `src/sources/osv/processor.ts` (move from `src/processor.ts`)
- Create: `src/sources/osv/schema.ts` (move from `src/schema.ts`)
- Create: `src/sources/osv/severity.ts` (move from `src/severity.ts`)
- Create: `src/sources/osv/semver.ts` (move from `src/semver.ts`)
- Test: `src/__tests__/sources/osv.test.ts`

**Step 1: Write integration test for OSV source**

```typescript
import { describe, expect, test, beforeEach } from "bun:test"
import { OSVSource } from "~/sources/osv"
import type { VulnerabilitySource } from "~/sources/types"

describe("OSVSource", () => {
  beforeEach(() => {
    process.env.BUN_SCAN_LOG_LEVEL = "error"
  })

  test("implements VulnerabilitySource interface", () => {
    const source: VulnerabilitySource = new OSVSource({})
    expect(source.name).toBe("osv")
    expect(typeof source.scan).toBe("function")
  })

  test("returns empty array for empty packages", async () => {
    const source = new OSVSource({})
    const result = await source.scan([])
    expect(result).toEqual([])
  })
})
```

**Step 2: Run test to verify it fails**

Run: `bun test src/__tests__/sources/osv.test.ts`
Expected: FAIL

**Step 3: Create sources/osv directory and move files**

Move files and update imports:

- `src/client.ts` → `src/sources/osv/client.ts`
- `src/processor.ts` → `src/sources/osv/processor.ts`
- `src/schema.ts` → `src/sources/osv/schema.ts`
- `src/severity.ts` → `src/sources/osv/severity.ts`
- `src/semver.ts` → `src/sources/osv/semver.ts`

Update all internal imports in moved files to use relative paths within the osv directory.

**Step 4: Create OSVSource wrapper class**

Create `src/sources/osv/index.ts`:

```typescript
import type { VulnerabilitySource } from "../types.js"
import type { IgnoreConfig } from "../../config.js"
import { OSVClient } from "./client.js"
import { VulnerabilityProcessor } from "./processor.js"
import { logger } from "../../logger.js"
import { compileIgnoreConfig } from "../../config.js"

/**
 * OSV.dev vulnerability source
 * Queries Google's OSV database for npm package vulnerabilities
 */
export class OSVSource implements VulnerabilitySource {
  readonly name = "osv"
  private readonly client: OSVClient
  private readonly processor: VulnerabilityProcessor

  constructor(ignoreConfig: IgnoreConfig) {
    this.client = new OSVClient()
    this.processor = new VulnerabilityProcessor(ignoreConfig)
  }

  async scan(packages: Bun.Security.Package[]): Promise<Bun.Security.Advisory[]> {
    logger.info(`[OSV] Starting scan for ${packages.length} packages`)

    const vulnerabilities = await this.client.queryVulnerabilities(packages)
    const advisories = this.processor.processVulnerabilities(vulnerabilities, packages)

    logger.info(`[OSV] Scan complete: ${advisories.length} advisories found`)
    return advisories
  }
}
```

**Step 5: Run test to verify it passes**

Run: `bun test src/__tests__/sources/osv.test.ts`
Expected: PASS

**Step 6: Run full test suite to ensure no regressions**

Run: `bun test`
Expected: All existing tests pass

**Step 7: Commit**

```bash
git add src/sources/osv/
git commit -m "refactor(osv): extract OSV implementation to sources/osv/"
```

---

## Task 5: Fix npm bulk response parsing (Issue #1)

**Files:**

- Modify: `src/sources/npm/schema.ts`
- Modify: `src/sources/npm/client.ts`
- Test: `src/__tests__/sources/npm.test.ts`

**Step 1: Write failing test for bulk response shape**

Add a fixture-based test that parses the npm bulk response shape documented in https://github.com/bun-security-scanner/npm/issues/1#issue-3663080276 (record of package -> advisory[]). Include a `cvss.vectorString: null` to cover the nullable case.

**Root cause notes:** npm returns a record of package name to advisory array, not a record of advisory ID to advisory. The schema currently expects `advisories` to be a record of objects, which fails with `Invalid input: expected record, received undefined`. Fix the schema to match the actual bulk response and flatten arrays in the client.

```typescript
import { describe, expect, test } from "bun:test"
import { NpmAuditResponseSchema } from "~/sources/npm/schema"

describe("npm bulk response parsing", () => {
  test("parses package->advisory[] response", () => {
    const response = {
      cookie: [
        {
          id: 1103907,
          url: "https://github.com/advisories/GHSA-pxg6-pf52-xh8x",
          title: "cookie accepts cookie name, path, and domain with out of bounds characters",
          severity: "low",
          vulnerable_versions: "<0.7.0",
          cwe: ["CWE-74"],
          cvss: {
            score: 0,
            vectorString: null,
          },
        },
      ],
    }

    const parsed = NpmAuditResponseSchema.parse(response)
    expect(parsed.cookie).toHaveLength(1)
  })
})
```

**Step 2: Run test to verify it fails**

Run: `bun test src/__tests__/sources/npm.test.ts -t "npm bulk response parsing"`
Expected: FAIL with invalid_type on advisories

**Step 3: Update schema to match npm bulk response**

- Change `NpmAuditResponseSchema` to `z.record(z.string(), z.array(NpmAdvisorySchema))`.
- Allow `cvss.vectorString` to be `null` (`z.string().nullable().optional()`).
- Keep `NpmAuditResponseAltSchema` for `{ advisories: Record<string, NpmAdvisory[]> }`.

**Step 4: Update client parsing to handle advisory arrays**

Update `NpmAuditClient.executeBulkQuery` to flatten advisory arrays from the record values before returning.

**Step 5: Run test to verify it passes**

Run: `bun test src/__tests__/sources/npm.test.ts -t "npm bulk response parsing"`
Expected: PASS

**Step 6: Commit**

```bash
git add src/sources/npm/schema.ts src/sources/npm/client.ts src/__tests__/sources/npm.test.ts
git commit -m "fix(npm): handle bulk advisory response format"
```

---

## Task 6: Create npm Source Implementation

**Files:**

- Create: `src/sources/npm/index.ts`
- Create: `src/sources/npm/client.ts` (adapt from `npm/src/client.ts`)
- Create: `src/sources/npm/processor.ts` (adapt from `npm/src/processor.ts`)
- Create: `src/sources/npm/schema.ts` (adapt from `npm/src/schema.ts`)
- Create: `src/sources/npm/severity.ts` (adapt from `npm/src/severity.ts`)
- Create: `src/sources/npm/constants.ts` (adapt from `npm/src/constants.ts`)
- Test: `src/__tests__/sources/npm.test.ts`
- Test: `src/__tests__/constants.test.ts` (updated for BUN_SCAN_LOG_LEVEL)

**Step 1: Write integration test for npm source**

```typescript
import { describe, expect, test, beforeEach } from "bun:test"
import { NpmSource } from "~/sources/npm"
import type { VulnerabilitySource } from "~/sources/types"

describe("NpmSource", () => {
  beforeEach(() => {
    process.env.BUN_SCAN_LOG_LEVEL = "error"
  })

  test("implements VulnerabilitySource interface", () => {
    const source: VulnerabilitySource = new NpmSource({})
    expect(source.name).toBe("npm")
    expect(typeof source.scan).toBe("function")
  })

  test("returns empty array for empty packages", async () => {
    const source = new NpmSource({})
    const result = await source.scan([])
    expect(result).toEqual([])
  })
})
```

**Step 2: Run test to verify it fails**

Run: `bun test src/__tests__/sources/npm.test.ts`
Expected: FAIL

**Step 3: Adapt npm scanner files to sources/npm/**

Copy and adapt files from `npm/src/`:

- Update imports to use shared logger from `../../logger.js`
- Update imports to use shared retry from `../../retry.js`
- Update constants to use `NPM_` prefix for env vars where they remain (registry URL, timeout)
- Ensure semicolon-free style matches project conventions
- Map logging to `BUN_SCAN_LOG_LEVEL` (shared logger) and update docs/tests that referenced `NPM_SCANNER_LOG_LEVEL`

Key adaptations needed:

1. Remove duplicate logger (use shared)
2. Remove duplicate retry (use shared)
3. Use project's code style (no semicolons)
4. Support ignore config like OSV source does
5. Align log level env var to `BUN_SCAN_LOG_LEVEL`

**Step 4: Create NpmSource wrapper class**

Create `src/sources/npm/index.ts`:

```typescript
import type { VulnerabilitySource } from "../types.js"
import type { IgnoreConfig } from "../../config.js"
import { NpmAuditClient } from "./client.js"
import { AdvisoryProcessor } from "./processor.js"
import { logger } from "../../logger.js"

/**
 * npm Registry vulnerability source
 * Queries npm's bulk advisory API backed by GitHub Advisory Database
 */
export class NpmSource implements VulnerabilitySource {
  readonly name = "npm"
  private readonly client: NpmAuditClient
  private readonly processor: AdvisoryProcessor
  private readonly ignoreConfig: IgnoreConfig

  constructor(ignoreConfig: IgnoreConfig) {
    this.client = new NpmAuditClient()
    this.processor = new AdvisoryProcessor()
    this.ignoreConfig = ignoreConfig
  }

  async scan(packages: Bun.Security.Package[]): Promise<Bun.Security.Advisory[]> {
    logger.info(`[npm] Starting scan for ${packages.length} packages`)

    const advisories = await this.client.queryVulnerabilities(packages)
    const bunAdvisories = this.processor.processAdvisories(advisories, packages)

    // TODO: Apply ignore config filtering (Task 7)

    logger.info(`[npm] Scan complete: ${bunAdvisories.length} advisories found`)
    return bunAdvisories
  }
}
```

**Step 5: Run test to verify it passes**

Run: `bun test src/__tests__/sources/npm.test.ts`
Expected: PASS

**Step 6: Commit**

```bash
git add src/sources/npm/
git commit -m "feat(npm): add npm Registry vulnerability source"
```

---

## Task 7: Add Ignore Config + Alias Support to npm Source

**Files:**

- Modify: `src/sources/npm/processor.ts`
- Modify: `src/sources/npm/index.ts`
- Test: `src/__tests__/sources/npm.test.ts`

**Step 1: Write tests for ignore filtering and alias support**

Add to npm source tests (unit-test the processor with fixtures rather than hitting the registry):

```typescript
describe("ignore configuration", () => {
  test("ignores globally ignored advisories by id", () => {
    const processor = new AdvisoryProcessor({ ignore: ["GHSA-test-1234-5678"] })
    // Assert GHSA ID is filtered
  })

  test("ignores globally ignored advisories by CVE alias", () => {
    const processor = new AdvisoryProcessor({ ignore: ["CVE-2024-1234"] })
    // Advisory has cves: ["CVE-2024-1234"] and should be filtered
  })

  test("ignores package-specific vulnerabilities", () => {
    const processor = new AdvisoryProcessor({
      packages: {
        "test-pkg": {
          vulnerabilities: ["CVE-2024-1234"],
          reason: "Not affected in our usage",
        },
      },
    })
    // Assert only test-pkg is filtered for that CVE
  })
})
```

**Step 2: Run test to verify it fails**

Run: `bun test src/__tests__/sources/npm.test.ts -t "ignore configuration"`
Expected: FAIL

**Step 3: Update AdvisoryProcessor to support ignore config + aliases**

Pass compiled ignore config to processor and include aliases for npm advisories:

```typescript
import {
  type IgnoreConfig,
  type CompiledIgnoreConfig,
  compileIgnoreConfig,
  shouldIgnoreVulnerability,
} from "../../config.js"

export class AdvisoryProcessor {
  private readonly compiledIgnoreConfig: CompiledIgnoreConfig
  private ignoredCount = 0

  constructor(ignoreConfig: IgnoreConfig = {}) {
    this.compiledIgnoreConfig = compileIgnoreConfig(ignoreConfig)
  }

  // In processAdvisory, add check:
  const aliases = [
    ...(advisory.cves ?? []),
    ...(advisory.github_advisory_id ? [advisory.github_advisory_id] : []),
  ]

  const ignoreResult = shouldIgnoreVulnerability(
    String(advisory.id),
    aliases,
    pkg.name,
    this.compiledIgnoreConfig,
  )

  if (ignoreResult.ignored) {
    logger.debug(`Ignoring ${advisory.id} for ${pkg.name}: ${ignoreResult.reason}`)
    this.ignoredCount++
    continue
  }
```

**Step 4: Run test to verify it passes**

Run: `bun test src/__tests__/sources/npm.test.ts`
Expected: PASS

**Step 5: Commit**

```bash
git add src/sources/npm/
git commit -m "feat(npm): add ignore config support to npm source"
```

---

## Task 8: Create Source Factory

**Files:**

- Create: `src/sources/factory.ts`
- Test: `src/__tests__/sources/factory.test.ts`

**Step 1: Write factory tests**

```typescript
import { describe, expect, test } from "bun:test"
import { createSource, createSources } from "~/sources/factory"
import { OSVSource } from "~/sources/osv"
import { NpmSource } from "~/sources/npm"

describe("createSource", () => {
  const emptyConfig = {}

  test("creates OSV source for 'osv'", () => {
    const source = createSource("osv", emptyConfig)
    expect(source).toBeInstanceOf(OSVSource)
    expect(source.name).toBe("osv")
  })

  test("creates npm source for 'npm'", () => {
    const source = createSource("npm", emptyConfig)
    expect(source).toBeInstanceOf(NpmSource)
    expect(source.name).toBe("npm")
  })

  test("throws for invalid source type", () => {
    expect(() => createSource("invalid" as any, emptyConfig)).toThrow()
  })
})

describe("createSources", () => {
  const emptyConfig = {}

  test("returns single source for 'osv'", () => {
    const sources = createSources("osv", emptyConfig)
    expect(sources).toHaveLength(1)
    expect(sources[0].name).toBe("osv")
  })

  test("returns single source for 'npm'", () => {
    const sources = createSources("npm", emptyConfig)
    expect(sources).toHaveLength(1)
    expect(sources[0].name).toBe("npm")
  })

  test("returns both sources for 'both'", () => {
    const sources = createSources("both", emptyConfig)
    expect(sources).toHaveLength(2)
    expect(sources.map((s) => s.name).sort()).toEqual(["npm", "osv"])
  })
})
```

**Step 2: Run test to verify it fails**

Run: `bun test src/__tests__/sources/factory.test.ts`
Expected: FAIL

**Step 3: Implement source factory**

```typescript
import type { VulnerabilitySource, SourceType } from "./types.js"
import type { IgnoreConfig } from "../config.js"
import { OSVSource } from "./osv/index.js"
import { NpmSource } from "./npm/index.js"

/**
 * Create a single vulnerability source by type
 */
export function createSource(type: "osv" | "npm", ignoreConfig: IgnoreConfig): VulnerabilitySource {
  switch (type) {
    case "osv":
      return new OSVSource(ignoreConfig)
    case "npm":
      return new NpmSource(ignoreConfig)
    default:
      throw new Error(`Unknown source type: ${type}`)
  }
}

/**
 * Create vulnerability sources based on config
 * Returns array to support 'both' mode
 */
export function createSources(type: SourceType, ignoreConfig: IgnoreConfig): VulnerabilitySource[] {
  switch (type) {
    case "osv":
      return [new OSVSource(ignoreConfig)]
    case "npm":
      return [new NpmSource(ignoreConfig)]
    case "both":
      return [new OSVSource(ignoreConfig), new NpmSource(ignoreConfig)]
    default:
      throw new Error(`Unknown source type: ${type}`)
  }
}
```

**Step 4: Run test to verify it passes**

Run: `bun test src/__tests__/sources/factory.test.ts`
Expected: PASS

**Step 5: Commit**

```bash
git add src/sources/factory.ts src/__tests__/sources/factory.test.ts
git commit -m "feat(sources): add source factory for dynamic source selection"
```

---

## Task 9: Create Multi-Source Scanner with Alias-Aware Deduplication

**Files:**

- Create: `src/sources/multi.ts`
- Test: `src/__tests__/sources/multi.test.ts`
- Modify: `src/types.ts` (add optional advisory aliases)
- Modify: `src/sources/osv/processor.ts` (populate aliases)
- Modify: `src/sources/npm/processor.ts` (populate aliases)

**Step 1: Write multi-source scanner tests**

```typescript
import { describe, expect, test } from "bun:test"
import { MultiSourceScanner } from "~/sources/multi"
import type { VulnerabilitySource } from "~/sources/types"

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

describe("MultiSourceScanner", () => {
  test("runs single source and returns results", async () => {
    const mockSource: VulnerabilitySource = {
      name: "mock",
      async scan() {
        return [makeAdvisory({ id: "CVE-1", package: "test-pkg" })]
      },
    }

    const scanner = new MultiSourceScanner([mockSource])
    const results = await scanner.scan([{ name: "test-pkg", version: "1.0.0" }])

    expect(results).toHaveLength(1)
    expect(results[0].id).toBe("CVE-1")
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

    const scanner = new MultiSourceScanner([source1, source2])
    const results = await scanner.scan([{ name: "pkg", version: "1.0.0" }])

    // Should have 3 unique vulnerabilities
    expect(results).toHaveLength(3)

    // CVE-1 should take the highest severity (fatal from source2)
    const cve1 = results.find((r) => r.id === "CVE-1" || r.aliases?.includes("CVE-1"))
    expect(cve1?.level).toBe("fatal")
  })

  test("queries sources in parallel", async () => {
    let slowDone = false
    let fastDone = false

    const slowSource: VulnerabilitySource = {
      name: "slow",
      async scan() {
        await Bun.sleep(100)
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

    const scanner = new MultiSourceScanner([slowSource, fastSource])
    await scanner.scan([])

    expect(fastDone).toBe(true)
    expect(slowDone).toBe(true)
  })
})
```

**Step 2: Run test to verify it fails**

Run: `bun test src/__tests__/sources/multi.test.ts`
Expected: FAIL

**Step 3: Extend advisory shape to carry aliases**

In `src/types.ts`, extend `Bun.Security.Advisory` to include an optional `aliases?: string[]` field (used only for deduplication and ignore matching).

**Step 4: Ensure OSV and npm processors populate aliases**

- OSV advisories: set `aliases: vuln.aliases ?? []`
- npm advisories: set `aliases: [ ...(advisory.cves ?? []), ...(advisory.github_advisory_id ? [advisory.github_advisory_id] : []) ]`
- Always include `id` and `aliases` in dedupe keys so CVE/GHSA pairs merge across sources.

**Step 5: Implement MultiSourceScanner with alias-aware dedupe**

```typescript
import type { VulnerabilitySource } from "./types.js"
import { logger } from "../logger.js"

/**
 * Scanner that queries multiple vulnerability sources in parallel
 * Deduplicates results and takes highest severity for duplicates
 */
export class MultiSourceScanner {
  private readonly sources: VulnerabilitySource[]

  constructor(sources: VulnerabilitySource[]) {
    if (sources.length === 0) {
      throw new Error("MultiSourceScanner requires at least one source")
    }
    this.sources = sources
  }

  async scan(packages: Bun.Security.Package[]): Promise<Bun.Security.Advisory[]> {
    if (packages.length === 0) {
      return []
    }

    const sourceNames = this.sources.map((s) => s.name).join(", ")
    logger.info(`Scanning with sources: ${sourceNames}`)

    // Query all sources in parallel
    const results = await Promise.allSettled(this.sources.map((source) => source.scan(packages)))

    // Collect all advisories
    const allAdvisories: Bun.Security.Advisory[] = []

    for (let i = 0; i < results.length; i++) {
      const result = results[i]
      const source = this.sources[i]

      if (result.status === "fulfilled") {
        logger.info(`[${source.name}] Found ${result.value.length} advisories`)
        allAdvisories.push(...result.value)
      } else {
        logger.error(`[${source.name}] Scan failed`, {
          error: result.reason instanceof Error ? result.reason.message : String(result.reason),
        })
      }
    }

    return this.deduplicateAdvisories(allAdvisories)
  }

  /**
   * Deduplicate advisories by package + any overlapping id/alias
   * When duplicates exist, keep the one with highest severity (fatal > warn)
   */
  private deduplicateAdvisories(advisories: Bun.Security.Advisory[]): Bun.Security.Advisory[] {
    const map = new Map<string, Bun.Security.Advisory>()

    for (const advisory of advisories) {
      const ids = new Set([advisory.id, ...(advisory.aliases ?? [])])
      const packageKey = advisory.package

      // Find an existing advisory with overlapping id/alias for this package
      let existingKey: string | null = null
      for (const id of ids) {
        const key = `${packageKey}:${id}`
        if (map.has(key)) {
          existingKey = key
          break
        }
      }

      if (!existingKey) {
        for (const id of ids) {
          map.set(`${packageKey}:${id}`, advisory)
        }
        continue
      }

      const existing = map.get(existingKey)
      if (!existing) continue

      const winner = this.isHigherSeverity(advisory.level, existing.level) ? advisory : existing
      for (const id of ids) {
        map.set(`${packageKey}:${id}`, winner)
      }
    }

    // De-dupe map values (multiple keys point at same object)
    return Array.from(new Set(map.values()))
  }

  private isHigherSeverity(
    a: Bun.Security.Advisory["level"],
    b: Bun.Security.Advisory["level"],
  ): boolean {
    const priority: Record<string, number> = { fatal: 2, warn: 1 }
    return (priority[a] ?? 0) > (priority[b] ?? 0)
  }
}
```

**Step 6: Run test to verify it passes**

Run: `bun test src/__tests__/sources/multi.test.ts`
Expected: PASS

**Step 7: Commit**

```bash
git add src/sources/multi.ts src/__tests__/sources/multi.test.ts src/types.ts

git commit -m "feat(sources): add alias-aware multi-source deduplication"
```

---

## Task 10: Update Main Scanner Entry Point

**Files:**

- Modify: `src/index.ts`
- Test: `src/__tests__/scanner.test.ts`

**Step 1: Write integration test for configurable source**

Add to scanner tests:

```typescript
describe("source configuration", () => {
  test("uses OSV source by default", async () => {
    // Write config without source field
    await Bun.write(".bun-scan.json", JSON.stringify({}))

    // Scanner should use OSV
    // (Test by checking log output or mock)
  })

  test("uses npm source when configured", async () => {
    await Bun.write(".bun-scan.json", JSON.stringify({ source: "npm" }))

    // Scanner should use npm
  })

  test("uses both sources when configured", async () => {
    await Bun.write(".bun-scan.json", JSON.stringify({ source: "both" }))

    // Scanner should query both and deduplicate
  })
})
```

**Step 2: Run test to verify it fails**

Run: `bun test src/__tests__/scanner.test.ts -t "source configuration"`
Expected: FAIL

**Step 3: Update index.ts to use source factory**

```typescript
/// <reference types="bun-types" />
import "./types.js"
import { loadConfig } from "./config.js"
import { createSources } from "./sources/factory.js"
import { MultiSourceScanner } from "./sources/multi.js"
import { logger } from "./logger.js"

/**
 * Bun Security Scanner with configurable vulnerability sources
 * Supports OSV.dev, npm Registry, or both
 */
export const scanner: Bun.Security.Scanner = {
  version: "1",

  async scan({ packages }) {
    try {
      logger.info(`Starting vulnerability scan for ${packages.length} packages`)

      // Load configuration (includes source and ignore rules)
      const config = await loadConfig()

      // Create vulnerability sources based on config
      const sources = createSources(config.source ?? "osv", config)

      // Scan with all configured sources
      const multiScanner = new MultiSourceScanner(sources)
      const advisories = await multiScanner.scan(packages)

      logger.info(
        `Scan completed: ${advisories.length} advisories found for ${packages.length} packages`,
      )

      return advisories
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      logger.error("Scanner encountered an unexpected error", {
        error: message,
      })

      // Fail-safe: allow installation to proceed on scanner errors
      return []
    }
  },
}

// CLI entry point
if (import.meta.main) {
  const { runCli } = await import("./cli.js")
  await runCli()
}
```

**Step 4: Run test to verify it passes**

Run: `bun test src/__tests__/scanner.test.ts`
Expected: PASS

**Step 5: Run full test suite**

Run: `bun test`
Expected: All tests pass

**Step 6: Run full check**

Run: `bun check`
Expected: Format, lint, compile, and tests all pass

**Step 7: Commit**

```bash
git add src/index.ts
git commit -m "feat: add configurable multi-source scanning"
```

---

## Task 11: Update Legacy Imports and Re-exports

**Files:**

- Modify: `src/schema.ts` → re-export from sources/osv
- Modify: `src/client.ts` → re-export from sources/osv
- Modify: `src/processor.ts` → re-export from sources/osv
- Modify: `src/severity.ts` → re-export from sources/osv
- Modify: `src/semver.ts` → re-export from sources/osv

**Step 1: Create re-export files for backwards compatibility**

For each file, replace content with re-exports:

`src/schema.ts`:

```typescript
// Re-export from sources/osv for backwards compatibility
export * from "./sources/osv/schema.js"
```

`src/client.ts`:

```typescript
// Re-export from sources/osv for backwards compatibility
export * from "./sources/osv/client.js"
```

(Similar for processor.ts, severity.ts, semver.ts)

**Step 2: Run full test suite**

Run: `bun test`
Expected: All tests pass (imports still work)

**Step 3: Run full check**

Run: `bun check`
Expected: All checks pass

**Step 4: Commit**

```bash
git add src/schema.ts src/client.ts src/processor.ts src/severity.ts src/semver.ts
git commit -m "refactor: add re-exports for backwards compatibility"
```

---

## Task 12: Update Documentation and README

**Files:**

- Modify: `README.md`

**Step 1: Add source configuration + dedupe/ignore notes**

Add after existing configuration documentation:

````markdown
### Vulnerability Sources

Configure which vulnerability database to query:

```json
{
  "source": "osv"
}
```
````

| Source          | Description                                                 |
| --------------- | ----------------------------------------------------------- |
| `osv` (default) | Query OSV.dev (Google's Open Source Vulnerability database) |
| `npm`           | Query npm Registry (GitHub Advisory Database)               |
| `both`          | Query both sources and deduplicate results                  |

Using `both` provides maximum coverage but takes longer as it queries two APIs.

#### Dedupe and Ignore Behavior

OSV and npm do not always share the same primary advisory IDs. bun-scan deduplicates by package when advisories share IDs or aliases (CVE or GHSA). Ignore rules are matched against advisory IDs and aliases, so you can ignore either `CVE-*` or `GHSA-*` for the same issue.

````

**Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add multi-source configuration documentation"
````

---

## Task 13: Final Verification and Cleanup

**Step 1: Run full check**

Run: `bun check`
Expected: All format, lint, compile, and test checks pass

**Step 2: Test each source mode manually**

```bash
# Test OSV (default)
echo '{}' > .bun-scan.json
bun run src/cli.ts scan

# Test npm
echo '{"source": "npm"}' > .bun-scan.json
bun run src/cli.ts scan

# Test both
echo '{"source": "both"}' > .bun-scan.json
bun run src/cli.ts scan
```

**Step 3: Clean up test config**

```bash
rm .bun-scan.json
```

**Step 4: Final commit**

```bash
git add .
git commit -m "chore: cleanup and final verification"
```

---

## Summary

After completing all tasks, the project will have:

1. ✅ Updated JSON schema with `source` field
2. ✅ `VulnerabilitySource` interface for abstraction
3. ✅ Config loading with source field support
4. ✅ OSV implementation extracted to `src/sources/osv/`
5. ✅ npm implementation added at `src/sources/npm/`
6. ✅ Ignore config support in npm source
7. ✅ Source factory for dynamic source creation
8. ✅ Fix npm bulk response parsing bug
9. ✅ Multi-source scanner with parallel queries and deduplication
10. ✅ Updated main entry point
11. ✅ Backwards-compatible re-exports
12. ✅ Updated documentation

**File Structure After:**

```
src/
├── sources/
│   ├── types.ts           # VulnerabilitySource interface
│   ├── factory.ts         # Source creation factory
│   ├── multi.ts           # Multi-source scanner
│   ├── osv/               # OSV.dev implementation
│   │   ├── index.ts
│   │   ├── client.ts
│   │   ├── processor.ts
│   │   ├── schema.ts
│   │   ├── severity.ts
│   │   └── semver.ts
│   └── npm/               # npm Registry implementation
│       ├── index.ts
│       ├── client.ts
│       ├── processor.ts
│       ├── schema.ts
│       ├── severity.ts
│       └── constants.ts
├── config.ts              # Updated with source field
├── index.ts               # Uses source factory
├── schema.ts              # Re-exports from sources/osv
├── client.ts              # Re-exports from sources/osv
├── processor.ts           # Re-exports from sources/osv
└── ...
```
