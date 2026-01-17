# AGENTS.md - Bun-Scan Coding Guidelines

## Project Overview

Bun-scan is an OSV vulnerability scanner for Bun projects implementing `Bun.Security.Scanner`. It queries Google's OSV.dev and npm registry to detect vulnerabilities in npm packages.

## Commands

```bash
# Full check - ALWAYS run before commits
bun check                              # format + lint + compile + test

# Individual
bun format                             # Format with oxfmt (no semicolons)
bun lint:check                         # Run oxlint
bun compile                            # TypeScript check (tsgo --noEmit)

# Testing
bun test                               # All tests
bun test src/__tests__/retry.test.ts   # Single file
bun test -t "pattern"                  # Match test names
bun test --watch                       # Watch mode
```

## TypeScript Rules

- **Strict mode** with `noUncheckedIndexedAccess` - array/object access may be `undefined`
- **No unused parameters** - `noUnusedParameters: true`
- **Verbatim imports** - use `import type` for type-only imports
- Path alias: `~/*` -> `./src/*`

## Code Style

### Imports

```typescript
// Type-only imports MUST use 'import type'
import type { OSVQuery, OSVVulnerability } from "./schema.js"

// Value imports separate
import { OSVResponseSchema } from "./schema.js"

// Always .js extension (even for .ts files)
import { logger } from "./logger.js"

// External deps first, then internal
import { z } from "zod"
import { logger } from "./logger.js"
```

### Naming

```typescript
// Classes: PascalCase
class OSVClient {}

// Functions: camelCase
function mapSeverityToLevel() {}

// Constants: SCREAMING_SNAKE_CASE objects
export const OSV_API = { BASE_URL: "...", TIMEOUT_MS: 30_000 } as const

// Types/Interfaces: PascalCase (no I prefix)
type LogLevel = "debug" | "info" | "warn" | "error"
interface RetryConfig {}
```

### Types

```typescript
// Explicit return types on exports
export function mapSeverity(vuln: OSVVulnerability): "fatal" | "warn" {}

// 'as const' for literal inference, 'satisfies' for type checking + literal preservation
export const FATAL_SEVERITIES = ["CRITICAL", "HIGH"] as const satisfies readonly FatalSeverity[]

// Zod for runtime validation
export const QuerySchema = z.object({...})
export type Query = z.infer<typeof QuerySchema>
```

### Error Handling

```typescript
// Extract error messages safely
const message = error instanceof Error ? error.message : String(error)

// Log with context
logger.error("Operation failed", {
  error: error instanceof Error ? error.message : String(error),
  context: additionalData,
})

// Fail-safe: return safe defaults on errors in critical paths
```

### Async Patterns

```typescript
// Prefer async/await over raw promises
async function fetchData(): Promise<Data[]> {
  const response = await fetch(url)
  return response.json()
}

// Promise.allSettled for parallel ops that may fail independently
const responses = await Promise.allSettled(queries.map((q) => process(q)))

// AbortSignal for timeouts
signal: AbortSignal.timeout(this.timeout)
```

### Class Structure

```typescript
export class OSVClient {
  private readonly baseUrl: string     // 1. Fields
  private readonly timeout: number

  constructor() { ... }                 // 2. Constructor

  async queryVulnerabilities() { ... }  // 3. Public methods

  private async executeBatch() { ... }  // 4. Private methods
}
```

## Testing

```typescript
import { beforeEach, describe, expect, test } from "bun:test"

describe("Feature", () => {
  beforeEach(() => {
    process.env.BUN_SCAN_LOG_LEVEL = "error"
  })

  test("describes expected behavior", async () => {
    const input = createTestInput()
    const result = await functionUnderTest(input)
    expect(result).toBe(expected)
  })
})
```

## File Structure

```
src/
  __tests__/           # Test files (*.test.ts)
  sources/
    osv/               # OSV.dev source (client, processor, schema, severity)
    npm/               # npm Registry source
    factory.ts         # Source factory
    multi.ts           # Multi-source scanner
  index.ts             # Entry point, exports scanner
  types.ts             # Global type declarations
  constants.ts         # Configuration constants
  config.ts            # Config loading
  logger.ts            # Logging utilities
  retry.ts             # Retry logic with exponential backoff
  cli.ts               # CLI interface
```

## Pre-commit (Lefthook)

Runs sequentially: `bun format` -> `bun lint:check` -> `bun compile`

## Key Dependencies

- **zod**: Runtime schema validation
- **oxfmt/oxlint**: Formatting and linting (no semicolons)
- **tsgo**: TypeScript compilation (native preview)

## Bun APIs

`Bun.file(path)`, `file.exists()`, `file.json()`, `Bun.semver.satisfies()`, `Bun.env[VAR]`
