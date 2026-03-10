# Implementation Plan: `failOnScannerError`

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers/executing-plans to implement this plan task-by-task.

## Goal

Add a `failOnScannerError` boolean config option (default `false`) that makes bun-scan fail-closed — any scanner error blocks `bun install` instead of silently returning `[]`. Mirrors Bun's own error = block behavior.

## Architecture

- New boolean field threaded through: config → scanner → multi-source scanner
- Env var `BUN_SCAN_FAIL_ON_SCANNER_ERROR` overrides config file (special precedence — bootstrap escape hatch)
- When `true`: any source-level failure throws → Bun blocks install
- When `false` (default): existing fail-open behavior preserved
- Source-internal batch/retry error handling unchanged (fail-closed applies at source level, not sub-request level)

## Semantic Contract

```
failOnScannerError: false (default)
  → scanner is advisory; errors logged, install proceeds

failOnScannerError: true
  → scanner is authoritative; any error blocks install
  → every configured source must succeed
  → source: "both" means BOTH must succeed
  → malformed config + env var set = block
  → config file missing (ENOENT) = NOT fatal (use defaults)
```

## Behavior Matrix

| `failOnScannerError` | Scenario | Result |
|---|---|---|
| `false` | Any error | Log, return `[]`, install proceeds |
| `true` | Config file malformed + env var set | **Throw** → block |
| `true` | Config file malformed + only in file | Can't read own value → default `false` → proceeds |
| `true` | Config file missing | Not fatal — use defaults, scan continues |
| `true` | Config file unreadable (EACCES) | **Throw** → block |
| `true` | Single source error | **Throw** → block |
| `true` | One of two sources fails (`both`) | **Throw** → block (incomplete scan) |
| `true` | All sources fail | **Throw** → block |
| `true` | Scanner crash | **Re-throw** → block |
| `true` | Invalid env var value | Ignored (treated as unset) |

## Error Messages

Short, explicit, user-actionable. Pattern:
```
bun-scan: scan failed for source "osv": <reason>. failOnScannerError=true requires all configured sources to succeed.
```

```
bun-scan: failed to load config file .bun-scan.json: <reason>. BUN_SCAN_FAIL_ON_SCANNER_ERROR=true makes config errors fatal.
```

## Scope Boundary

Source-internal error handling (batch retries, single vuln fetch failures) is **unchanged**. The fail-closed contract applies at the source level: if a source's `scan()` method throws, that's a scanner error. Internal partial failures within a source (after retries) are tolerated. This keeps the change focused and avoids threading config through source client interfaces.

---

## Task 1: Add `BUN_SCAN_FAIL_ON_SCANNER_ERROR` env var constant

**Files:** `packages/core/src/constants.ts`

Add to the `ENV` object at line 76:

```typescript
/** Fail on scanner error (strict mode) - overrides config file */
FAIL_ON_SCANNER_ERROR: "BUN_SCAN_FAIL_ON_SCANNER_ERROR",
```

**Verify:** `bun compile` passes

---

## Task 2: Add `failOnScannerError` to config schema, defaults, merge logic, and strict config loading

**Files:**
- `packages/core/src/config.ts`
- `packages/core/src/__tests__/config.test.ts`

### Tests first

Add two describe blocks to `config.test.ts`:

**`failOnScannerError configuration`:**
- defaults to `false` when not specified
- reads `failOnScannerError: true` from config file
- env var `true` overrides config file `false`
- env var `false` overrides config file `true`
- defaults to `false` when no config file exists

**`failOnScannerError strict config loading`:**
- throws on malformed JSON config when env var is `true`
- does NOT throw on malformed config when env var is not set (existing behavior)
- does NOT throw on missing config file when env var is `true`

### Implementation

**a) `CONFIG_DEFAULTS` (line 9):** Add `failOnScannerError: false`

**b) `ConfigSchema` (line 72):** Add `failOnScannerError: z.boolean().optional()`

**c) `mergeConfig()` (line 192):**
- Add `failOnScannerError: CONFIG_DEFAULTS.failOnScannerError` to initial merged object
- Add file config layering: `if (fileConfig.failOnScannerError !== undefined) merged.failOnScannerError = fileConfig.failOnScannerError`
- **AFTER file layering** (special precedence): resolve env var and override if set:
  ```typescript
  const envFailOnError = parseEnvBoolean(ENV.FAIL_ON_SCANNER_ERROR)
  if (envFailOnError !== undefined) merged.failOnScannerError = envFailOnError
  ```

**d) `loadConfig()` (line 237):** Resolve strict bootstrap before loading:
```typescript
export async function loadConfig(): Promise<Config> {
  const strictBootstrap = parseEnvBoolean(ENV.FAIL_ON_SCANNER_ERROR) === true

  for (const filename of CONFIG_FILES) {
    const config = await tryLoadConfigFile(filename, { fatalOnError: strictBootstrap })
    if (config) {
      return mergeConfig(config)
    }
  }

  return mergeConfig(null)
}
```

**e) `tryLoadConfigFile()` (line 252):** Add optional `{ fatalOnError?: boolean }` parameter. When `fatalOnError` is true and any error occurs (not ENOENT), throw with descriptive message instead of returning null.

**Verify:** `bun test packages/core/src/__tests__/config.test.ts` passes

---

## Task 3: Add `failOnScannerError` to JSON schema

**Files:** `schema/bun-scan.schema.json`

Add after `bunReportWarnings`:
```json
"failOnScannerError": {
  "type": "boolean",
  "default": false,
  "description": "Fail on scanner errors and block install. When true, any scanner error blocks installation instead of allowing it to proceed silently. The BUN_SCAN_FAIL_ON_SCANNER_ERROR environment variable overrides this setting. Recommended for CI environments."
}
```

**Verify:** `bun compile` passes

---

## Task 4: Make `createMultiSourceScanner` fail-closed when configured

**Files:**
- `packages/scanner/src/sources/multi.ts`
- `packages/scanner/src/__tests__/multi.test.ts`

### Tests first

Add `describe("failOnScannerError behavior")` to `multi.test.ts`:
- throws when any source fails and `failOnScannerError: true`
- throws with descriptive error containing source names and reasons
- does NOT throw on source failure when `failOnScannerError: false`
- does NOT throw on source failure when options not provided (backward compat)
- throws when all sources fail and `failOnScannerError: true`
- error message includes source name and error details

### Implementation

**a) Add options interface:**
```typescript
export interface MultiSourceScannerOptions {
  failOnScannerError?: boolean
}
```

**b) Update `createMultiSourceScanner` signature:**
```typescript
export function createMultiSourceScanner(
  sources: VulnerabilitySource[],
  options?: MultiSourceScannerOptions,
): MultiSourceScanner
```

**c) In `scan()` function:** After `Promise.allSettled`, collect failures into an array. If `failOnScannerError` is true and `failures.length > 0`, throw with aggregated error:
```typescript
if (failOnError && failures.length > 0) {
  const details = failures.map((f) => `${f.name}: ${f.error}`).join("; ")
  throw new Error(
    `bun-scan: scan failed for ${failures.length === 1 ? "source" : "sources"} ` +
      `${failures.map((f) => `"${f.name}"`).join(", ")}. ` +
      `Details: ${details}. ` +
      `failOnScannerError=true requires all configured sources to succeed.`,
  )
}
```

**d) Update exports in `packages/scanner/src/index.ts`:**
```typescript
export type { MultiSourceScanner, MultiSourceScannerOptions } from "./sources/multi.js"
```

**Verify:** `bun test packages/scanner/src/__tests__/multi.test.ts` passes

---

## Task 5: Make top-level scanner fail-closed when configured

**Files:**
- `packages/scanner/src/index.ts`
- `packages/scanner/src/__tests__/scanner.test.ts`

### Tests first

Add `describe("failOnScannerError behavior")` to `scanner.test.ts`:
- re-throws when `failOnScannerError: true` in config file (use unreachable source URL)
- re-throws when `BUN_SCAN_FAIL_ON_SCANNER_ERROR` env var is `true`
- does NOT throw when `failOnScannerError` is false (existing behavior preserved)

Note: use `http://127.0.0.1:1` as source URL to force connection refused. Clean up config files in `finally` blocks. Consider using `setSleep()` from `@repo/core` retry module to avoid retry delays in tests.

### Implementation

**a) Add helper function:**
```typescript
function parseFailOnScannerErrorEnv(): boolean {
  const value = Bun.env.BUN_SCAN_FAIL_ON_SCANNER_ERROR?.toLowerCase()
  return value === "true"
}
```

**b) Restructure `scan()` method:**
```typescript
async scan({ packages }) {
  let failOnScannerError = parseFailOnScannerErrorEnv()

  try {
    logger.debug(`Starting vulnerability scan for ${packages.length} packages`)

    const config = await loadConfig()
    const bunReportWarnings = config.bunReportWarnings ?? CONFIG_DEFAULTS.bunReportWarnings
    failOnScannerError = config.failOnScannerError ?? failOnScannerError

    const sources = createSources(config.source ?? "osv", config)
    const multiScanner = createMultiSourceScanner(sources, { failOnScannerError })
    const advisories = await multiScanner.scan(packages)

    // ... existing bunReportWarnings logic unchanged ...

    return advisories
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    logger.error("Scanner encountered an unexpected error", { error: message })

    if (failOnScannerError) {
      throw error
    }

    return []
  }
}
```

Key: `failOnScannerError` is declared before `try`. It's initialized from the env var (always available), then updated from config (if config loads). In the catch block, if config loading itself threw, the env var value is used. If config loaded successfully and set the value, the updated value is used.

**Verify:** `bun test packages/scanner/src/__tests__/scanner.test.ts` passes

---

## Task 6: Update type declarations

**Files:** `packages/scanner/types/index.d.ts`

Update `createMultiSourceScanner` signature to accept optional second argument:
```typescript
export function createMultiSourceScanner(
  sources: VulnerabilitySource[],
  options?: MultiSourceScannerOptions,
): MultiSourceScanner

export interface MultiSourceScannerOptions {
  failOnScannerError?: boolean
}
```

Also add `failOnScannerError` to the `Config` type if it's declared there.

**Verify:** `bun compile` passes

---

## Task 7: Update README.md

**Files:** `README.md`

Add `failOnScannerError` to:
1. The configuration options table/section
2. The environment variables section
3. Add a "Strict Mode (CI)" section explaining usage
4. Add example config for CI: `{ "failOnScannerError": true, "source": "npm" }`
5. Document that `source: "both"` + `failOnScannerError: true` means both backends must succeed

**Verify:** Read through for accuracy

---

## Task 8: Final verification

Run: `bun check` (format + lint + compile + test)

All must pass. Fix any formatting/lint/type issues.

---

## Notes for Implementer

- **No semicolons** — project uses oxfmt with `semi: false`
- **Use `import type`** for type-only imports (verbatimModuleSyntax)
- **Use `.js` extensions** in imports even for `.ts` files
- **Path alias `~/`** maps to `./src/` within each package
- **Tests use `bun:test`** — not Jest, not Vitest
- **Run `bun check` before final commit** — runs format + lint + compile + test
- **Env var cleanup in tests** — always use `try/finally` to clean up env vars and config files
- **Config file cleanup** — delete `.bun-scan.json` after tests, use existing `cleanupConfigFiles()` helper
