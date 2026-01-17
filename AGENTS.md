# AGENTS.md - Bun-Scan Coding Guidelines

This document provides coding standards and commands for AI agents working in this repository.

## Project Overview

Bun-scan is an OSV vulnerability scanner for Bun projects. It integrates with Google's OSV.dev database to detect vulnerabilities in npm packages and implements the `Bun.Security.Scanner` interface.

## Build/Lint/Test Commands

```bash
# Full check (format, lint, compile, test) - RECOMMENDED before commits
bun check

# Individual commands
bun format           # Format code with oxfmt
bun format:check     # Check formatting without fixing
bun lint             # Run oxlint
bun lint:check       # Run oxlint in check mode
bun compile          # TypeScript compilation (tsgo --noEmit)
bun dev              # Watch mode for development

# Testing
bun test                              # Run all tests
bun test src/__tests__/retry.test.ts  # Run single test file
bun test --watch                      # Watch mode
bun test --timeout 30000              # Custom timeout
bun test -t "test name pattern"       # Run tests matching pattern

# Clean build artifacts
bun clean
```

## Code Style Guidelines

### Formatting (oxfmt)

- **No semicolons** - configured in `.oxfmtrc.json`
- Use consistent indentation (2 spaces inferred)
- Run `bun format` before committing

### TypeScript Configuration

- **Strict mode enabled** - all strict checks active
- `noUncheckedIndexedAccess: true` - array/object access may be undefined
- `noUnusedParameters: true` - no unused function parameters
- `verbatimModuleSyntax: true` - use `import type` for type-only imports
- Target: ESNext with module preservation
- Path alias: `~/*` maps to `./src/*`

### Import Conventions

```typescript
// Type-only imports use 'import type'
import type { OSVQuery, OSVVulnerability } from "./schema.js"

// Value imports are separate
import { OSVResponseSchema, OSVBatchResponseSchema } from "./schema.js"

// Always use .js extension in imports (even for .ts files)
import { logger } from "./logger.js"

// Path alias for internal modules
import { withRetry } from "~/retry"

// External dependencies first, then internal modules
import { z } from "zod"
import { logger } from "./logger.js"
```

### Naming Conventions

```typescript
// Classes: PascalCase
class VulnerabilityProcessor {}
class OSVClient {}

// Functions/methods: camelCase
function mapSeverityToLevel() {}
async function queryVulnerabilities() {}

// Constants: SCREAMING_SNAKE_CASE for config objects
export const OSV_API = { BASE_URL: "...", TIMEOUT_MS: 30_000 }
export const SECURITY = { CVSS_FATAL_THRESHOLD: 7.0 }

// Types: PascalCase
type LogLevel = "debug" | "info" | "warn" | "error"
type FatalSeverity = "CRITICAL" | "HIGH"

// Interfaces: PascalCase (no I prefix)
interface RetryConfig {}
interface Logger {}

// Private class members: no prefix, use private keyword
private readonly baseUrl: string
```

### Type Annotations

```typescript
// Explicit return types on public functions
export function mapSeverityToLevel(vuln: OSVVulnerability): "fatal" | "warn" {}

// Use 'as const' for literal type inference
export const FATAL_SEVERITIES = ["CRITICAL", "HIGH"] as const

// Use 'satisfies' for type checking while preserving literal types
["CRITICAL", "HIGH"] as const satisfies readonly FatalSeverity[]

// Zod schemas for runtime validation
export const OSVQuerySchema = z.object({...})
export type OSVQuery = z.infer<typeof OSVQuerySchema>
```

### Error Handling

```typescript
// Wrap error message extraction
const message = error instanceof Error ? error.message : String(error)

// Log errors with context
logger.error("Operation failed", {
  error: error instanceof Error ? error.message : String(error),
  context: additionalData,
})

// Fail-safe: return safe defaults on errors in critical paths
try {
  // operation
} catch (error) {
  logger.error("Unexpected error", { error: ... })
  return [] // Safe default
}

// Use custom error checking for retry logic
shouldRetry: (error: Error) => {
  if (error.message.includes("404")) return false
  return true
}
```

### Async/Await Patterns

```typescript
// Prefer async/await over raw promises
async function fetchData(): Promise<Data[]> {
  const response = await fetch(url)
  return response.json()
}

// Use Promise.allSettled for parallel operations that may fail independently
const responses = await Promise.allSettled(queries.map((query) => this.querySinglePackage(query)))

// Process settled promises
for (const response of responses) {
  if (response.status === "fulfilled") {
    results.push(response.value)
  }
}

// Use AbortSignal for timeouts
signal: AbortSignal.timeout(this.timeout)
```

### Class Structure

```typescript
export class OSVClient {
  // 1. Private readonly fields first
  private readonly baseUrl: string
  private readonly timeout: number

  // 2. Constructor
  constructor() {
    this.baseUrl = getConfig(ENV.API_BASE_URL, OSV_API.BASE_URL)
  }

  // 3. Public methods
  async queryVulnerabilities(packages: Package[]): Promise<Vulnerability[]> {}

  // 4. Private methods (implementation details)
  private async executeBatchQuery(queries: Query[]): Promise<string[]> {}
}
```

### Documentation

```typescript
/**
 * Brief description of what this does
 * Additional context if needed
 */
export function functionName(): ReturnType {}

// Use JSDoc for public APIs, skip for obvious private methods
```

### Testing Conventions

```typescript
import { beforeEach, describe, expect, test } from "bun:test"

describe("FeatureName", () => {
  beforeEach(() => {
    // Setup, e.g., set log level
    process.env.BUN_SCAN_LOG_LEVEL = "error"
  })

  describe("SubCategory", () => {
    test("describes expected behavior", async () => {
      // Arrange
      const input = createTestInput()

      // Act
      const result = await functionUnderTest(input)

      // Assert
      expect(result).toBe(expected)
    })

    test("handles edge case", async () => {
      // Use descriptive test names
    })
  })
})
```

### Constants Organization

```typescript
// Group related constants in objects
export const OSV_API = {
  BASE_URL: "https://api.osv.dev/v1",
  TIMEOUT_MS: 30_000,
  MAX_BATCH_SIZE: 1_000,
} as const

// Use getConfig for environment overrides
export function getConfig<T>(envVar: string, defaultValue: T): T {
  const envValue = Bun.env[envVar]
  if (!envValue) return defaultValue
  // Type-safe parsing...
}
```

## File Organization

```
src/
  __tests__/          # Test files (*.test.ts)
  index.ts            # Main entry point, exports scanner
  types.ts            # Global type declarations
  schema.ts           # Zod schemas and derived types
  constants.ts        # Configuration constants
  client.ts           # OSV API client
  processor.ts        # Vulnerability processing
  logger.ts           # Logging utilities
  cli.ts              # CLI interface
```

## Pre-commit Hooks (Lefthook)

Pre-commit runs sequentially:

1. `bun format` - Auto-fix formatting
2. `bun lint:check` - Lint check
3. `bun compile` - Type check

## Key Dependencies

- **zod**: Runtime schema validation
- **@types/bun**: Bun type definitions
- **oxfmt/oxlint**: Formatting and linting
- **tsgo**: TypeScript compilation (native preview)

## Bun-Specific APIs

```typescript
// File operations
const file = Bun.file(path)
await file.exists()
await file.json()

// Semver utilities
Bun.semver.satisfies(version, range)

// Environment variables
Bun.env[VAR_NAME]
```
