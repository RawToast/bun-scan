# Bun-Scan

A security scanner for [Bun](https://bun.sh/) that checks packages for known vulnerabilities during installation.

[![npm version](https://img.shields.io/npm/v/bun-scan?color=dc2626)](https://npmjs.com/package/bun-scan)
[![npm downloads](https://img.shields.io/npm/dm/bun-scan?color=dc2626)](https://npmjs.com/package/bun-scan)
[![License: MIT](https://img.shields.io/badge/License-MIT-dc2626)](LICENSE)

## Features

- **Real-time Scanning**: Checks packages against configured sources (OSV, npm, or both) during installation
- **Batch Queries**: Efficient batch queries with deduplication
- **Fail-safe**: Does not block installations when the scanner fails
- **Configurable**: Supports config files and environment variables

## Installation

```bash
# Install as a dev dependency
bun add -d bun-scan
```

## Configuration

### 1. Enable the Scanner

Add to your `bunfig.toml`:

```toml
[install.security]
scanner = "bun-scan"
```

### 2. Optional: Ignore Specific Vulnerabilities

Create a `.bun-scan.json` file in your project root to ignore specific vulnerabilities:

Note to set the schema version in the URL to the correct version:

```json
{
  "$schema": "https://raw.githubusercontent.com/rawtoast/bun-scan/master/v1.1.0/bun-scan.schema.json",
  "packages": {
    "hono": {
      "vulnerabilities": ["CVE-2026-22818"],
      "reason": "Project does not use JWT from hono"
    }
  }
}
```

**Example: Global ignore**

```json
{
  "$schema": "https://raw.githubusercontent.com/rawtoast/bun-scan/master/schema/bun-scan.schema.json",
  "ignore": ["CVE-2024-1234", "GHSA-xxxx-xxxx-xxxx"]
}
```

**Example: Temporary ignore with expiration**

```json
{
  "$schema": "https://raw.githubusercontent.com/rawtoast/bun-scan/master/schema/bun-scan.schema.json",
  "packages": {
    "lodash": {
      "vulnerabilities": ["CVE-2021-23337"],
      "until": "2024-06-01",
      "reason": "Temporary ignore while migration is in progress"
    }
  }
}
```

### 3. Optional: Full Configuration

All settings can be configured via `.bun-scan.json`:

```json
{
  "$schema": "https://raw.githubusercontent.com/rawtoast/bun-scan/master/schema/bun-scan.schema.json",
  "source": "osv",
  "bunReportWarnings": true,
  "osv": {
    "apiBaseUrl": "https://api.osv.dev/v1",
    "timeoutMs": 30000,
    "disableBatch": false
  },
  "npm": {
    "registryUrl": "https://registry.npmjs.org",
    "timeoutMs": 30000
  }
}
```

#### Suppress Warning Prompts

Set `bunReportWarnings` to `false` to print warning-level advisories without triggering Bun's install prompt:

```json
{
  "bunReportWarnings": false
}
```

When disabled, warnings are still logged but won't require user confirmation during `bun install`. Fatal advisories (CRITICAL/HIGH severity) are always reported.

### 4. Optional: Environment Variables (Fallback)

Environment variables serve as fallbacks when config file values are not set:

```bash
# Logging level (debug, info, warn, error)
export BUN_SCAN_LOG_LEVEL=info

# OSV API configuration
export OSV_API_BASE_URL=https://api.osv.dev/v1
export OSV_TIMEOUT_MS=30000
export OSV_DISABLE_BATCH=false

# npm Registry configuration
export NPM_SCANNER_REGISTRY_URL=https://registry.npmjs.org
export NPM_SCANNER_TIMEOUT_MS=30000
```

**Precedence**: Config file values override environment variables, which override defaults.

### 5. Optional: Vulnerability Sources

Configure which vulnerability database to query:

```json
{
  "source": "osv"
}
```

| Source          | Description                                                 |
| --------------- | ----------------------------------------------------------- |
| `osv` (default) | Query OSV.dev (Google's Open Source Vulnerability database) |
| `npm`           | Query npm Registry (GitHub Advisory Database)               |
| `both`          | Query both sources and deduplicate results                  |

Using `both` provides maximum coverage but takes longer as it queries two APIs.

#### Dedupe and Ignore Behavior

When using `both`, advisories are deduplicated by package when they share IDs or aliases (CVE or GHSA). Ignore rules are matched against both advisory IDs and aliases.

### Advisory Levels

#### Fatal (Installation Blocked)

- **CVSS Score**: ≥ 7.0 (High/Critical)
- **Database Severity**: CRITICAL or HIGH
- **Action**: Installation is immediately blocked

#### Warning (User Prompted)

- **CVSS Score**: < 7.0 (Medium/Low)
- **Database Severity**: MEDIUM, LOW, or unspecified
- **Action**: User is prompted to continue or cancel

## Usage Examples

```bash
# Scanner runs automatically during installation
bun install express

bun add lodash@4.17.20
```

### Configuration Examples

```bash
# Increase timeout for slow networks
OSV_TIMEOUT_MS=60000 bun install

# Use custom OSV instance
OSV_API_BASE_URL=https://api.custom-osv.dev/v1 bun install
```

## Architecture

The scanner is built with a modular architecture:

```
src/
├── index.ts              # Main scanner implementation
├── config.ts             # Ignore configuration loading and validation
├── cli.ts                # CLI interface for testing
├── constants.ts          # Centralized configuration management
├── logger.ts             # Structured logging with configurable levels
├── retry.ts              # Robust retry logic with exponential backoff
├── sources/              # Vulnerability source integrations
│   ├── factory.ts        # Source selection and configuration
│   ├── multi.ts          # Multi-source aggregation and deduping
│   ├── osv/              # OSV.dev source implementation
│   └── npm/              # npm advisory source implementation
└── types.ts              # TypeScript type definitions
```

## Testing

```bash
# Run the test suite
bun test

# Run with coverage
bun test --coverage

# Type checking
bun run typecheck

# Linting
bun run lint
```

## Configuration Reference

### Config File Options

| Option              | Type    | Default                      | Description                                                     |
| ------------------- | ------- | ---------------------------- | --------------------------------------------------------------- |
| `source`            | string  | `"osv"`                      | Vulnerability source: `osv`, `npm`, or `both`                   |
| `bunReportWarnings` | boolean | `true`                       | Report warnings to Bun (causes prompt). Set `false` to suppress |
| `osv.apiBaseUrl`    | string  | `https://api.osv.dev/v1`     | OSV API base URL                                                |
| `osv.timeoutMs`     | number  | `30000`                      | OSV request timeout in milliseconds                             |
| `osv.disableBatch`  | boolean | `false`                      | Disable batch queries (use individual queries)                  |
| `npm.registryUrl`   | string  | `https://registry.npmjs.org` | npm registry URL                                                |
| `npm.timeoutMs`     | number  | `30000`                      | npm request timeout in milliseconds                             |

### Environment Variables (Fallback)

| Environment Variable       | Default                      | Description                             |
| -------------------------- | ---------------------------- | --------------------------------------- |
| `BUN_SCAN_LOG_LEVEL`       | `info`                       | Logging level: debug, info, warn, error |
| `OSV_API_BASE_URL`         | `https://api.osv.dev/v1`     | OSV API base URL                        |
| `OSV_TIMEOUT_MS`           | `30000`                      | Request timeout in milliseconds         |
| `OSV_DISABLE_BATCH`        | `false`                      | Disable batch queries                   |
| `NPM_SCANNER_REGISTRY_URL` | `https://registry.npmjs.org` | npm registry URL                        |
| `NPM_SCANNER_TIMEOUT_MS`   | `30000`                      | npm request timeout in milliseconds     |

> **Note**: `BUN_SCAN_LOG_LEVEL` must be set via environment variable for runtime control, as the logger initializes before the config file is loaded.

## Troubleshooting

### Common Issues

**Scanner not running during installation?**

- Verify `bunfig.toml` configuration
- Check that the package is installed as a dev dependency
- Enable debug logging: `BUN_SCAN_LOG_LEVEL=debug bun install`

**Network timeouts?**

- Increase timeout: `OSV_TIMEOUT_MS=60000`
- Check internet connectivity to osv.dev

**Too many false positives?**

- Check if you're using an outdated package version
- Use `.bun-scan.json` to ignore vulnerabilities that don't apply to your project

## License

MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **maloma7**: For the original implementation of the Bun OSV Scanner

## Related Projects

- [Bun Security Scanner API](https://bun.com/docs/install/security-scanner-api)
- [OSV.dev](https://osv.dev/)
- [Github advisories](https://github.com/advisories)
- [Bun OSV Scanner](https://github.com/bun-security-scanner/osv)
- [Bun NPM Scanner](https://github.com/bun-security-scanner/npm)
