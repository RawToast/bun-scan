<!--
Copyright (c) 2025 maloma7. All rights reserved.
SPDX-License-Identifier: MIT
-->

<img src="docs/icons/logo.svg" width="100%" alt="Bun OSV Scanner" />

# Bun OSV Scanner

A production-grade security scanner for [Bun](https://bun.sh/) that integrates with [OSV.dev](https://osv.dev/) (Open Source Vulnerabilities) to detect known vulnerabilities in npm packages during installation.

[![npm version](https://img.shields.io/npm/v/@bun-security-scanner/osv?color=dc2626)](https://npmjs.com/package/@bun-security-scanner/osv)
[![npm downloads](https://img.shields.io/npm/dm/@bun-security-scanner/osv?color=dc2626)](https://npmjs.com/package/@bun-security-scanner/osv)
[![License: MIT](https://img.shields.io/badge/License-MIT-dc2626)](LICENSE)
[![Built with Claude](https://img.shields.io/badge/Built_with-Claude-dc2626?style=flat&logo=claude&logoColor=dc2626)](https://anthropic.com/claude-code)
[![Checked with Biome](https://img.shields.io/badge/Checked_with-Biome-dc2626?style=flat&logo=biome&logoColor=dc2626)](https://biomejs.dev)
[![Secured with Lefthook](https://img.shields.io/badge/Secured_with-Lefthook-dc2626?style=flat&logo=lefthook&logoColor=dc2626)](https://lefthook.dev/)

## What is OSV.dev?

[OSV.dev](https://osv.dev/) is Google's open source vulnerability database that aggregates and distributes vulnerability information for open source projects. It provides:

- **Comprehensive Coverage**: Vulnerabilities from multiple sources (npm, PyPI, Go, Rust, etc.)
- **Structured Data**: Machine-readable vulnerability information with precise version ranges
- **Real-time Updates**: Continuously updated with the latest security advisories
- **Authoritative Source**: Maintained by Google and the open source community

## Features

- **Real-time Scanning**: Checks packages against OSV.dev during installation
- **High Performance**: Efficient batch queries with smart deduplication
- **Fail-safe**: Never blocks installations due to scanner errors
- **Structured Logging**: Configurable logging levels with contextual information
- **Precise Matching**: Accurate vulnerability-to-package version matching
- **Configurable**: Environment variable configuration for all settings
- **Well Tested**: Comprehensive test suite with edge case coverage

## Installation

**No API keys or registration required** - completely free to use with zero setup beyond installation.

```bash
# Install as a dev dependency
bun add -d @bun-security-scanner/osv
```

## Configuration

### 1. Enable the Scanner

Add to your `bunfig.toml`:

```toml
[install.security]
scanner = "@bun-security-scanner/osv"
```

### 2. Optional: Configuration Options

The scanner can be configured via environment variables:

```bash
# Logging level (debug, info, warn, error)
export OSV_LOG_LEVEL=info

# Custom OSV API base URL (optional)
export OSV_API_BASE_URL=https://api.osv.dev/v1

# Request timeout in milliseconds (default: 30000)
export OSV_TIMEOUT_MS=30000

# Disable batch queries (default: false)
export OSV_DISABLE_BATCH=false
```

## How It Works

### Security Scanning Process

1. **Package Detection**: Bun provides package information during installation
2. **Smart Deduplication**: Eliminates duplicate package@version queries
3. **Batch Querying**: Uses OSV.dev's efficient `/querybatch` endpoint
4. **Vulnerability Matching**: Precisely matches vulnerabilities to installed versions
5. **Severity Assessment**: Analyzes CVSS scores and database-specific severity
6. **Advisory Generation**: Creates actionable security advisories

### Advisory Levels

The scanner generates two types of security advisories:

#### Fatal (Installation Blocked)
- **CVSS Score**: ≥ 7.0 (High/Critical)
- **Database Severity**: CRITICAL or HIGH
- **Action**: Installation is immediately blocked
- **Examples**: Remote code execution, privilege escalation, data exposure

#### Warning (User Prompted)
- **CVSS Score**: < 7.0 (Medium/Low)
- **Database Severity**: MEDIUM, LOW, or unspecified
- **Action**: User is prompted to continue or cancel
- **TTY**: Interactive choice presented
- **Non-TTY**: Installation automatically cancelled
- **Examples**: Denial of service, information disclosure, deprecation warnings

### Error Handling Philosophy

The scanner follows a **fail-safe** approach:
- Network errors don't block installations
- Malformed responses are logged but don't halt the process
- Scanner crashes return empty advisory arrays (allows installation)
- Only genuine security threats should prevent package installation

## Usage Examples

### Basic Usage

```bash
# Scanner runs automatically during installation
bun install express
# -> Checks express and all dependencies for vulnerabilities

bun add lodash@4.17.20
# -> May warn about known lodash vulnerabilities in older versions
```

### Development Usage

```bash
# Enable debug logging to see detailed scanning information
OSV_LOG_LEVEL=debug bun install

# Test with a known vulnerable package
bun add event-stream@3.3.6
# -> Should trigger security advisory
```

### Configuration Examples

```bash
# Increase timeout for slow networks
OSV_TIMEOUT_MS=60000 bun install

# Use custom OSV instance (advanced)
OSV_API_BASE_URL=https://api.custom-osv.dev/v1 bun install
```

## Architecture

The scanner is built with a modular, production-ready architecture:

```
src/
├── index.ts              # Main scanner implementation
├── client.ts             # OSV.dev API client with batch support
├── processor.ts          # Vulnerability processing and advisory generation
├── cli.ts                # CLI interface for testing
├── schema.ts             # Zod schemas for OSV API responses
├── constants.ts          # Centralized configuration management
├── logger.ts             # Structured logging with configurable levels
├── retry.ts              # Robust retry logic with exponential backoff
├── semver.ts             # OSV semver range matching
├── severity.ts           # CVSS and severity assessment
└── types.ts              # TypeScript type definitions
```

### Key Design Principles

1. **Separation of Concerns**: Each module has a single, well-defined responsibility
2. **Error Isolation**: Failures in one component don't cascade to others
3. **Performance Optimization**: Batch processing, deduplication, and concurrent requests
4. **Observability**: Comprehensive logging for debugging and monitoring
5. **Type Safety**: Full TypeScript coverage with runtime validation

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

### Test Coverage

- Known vulnerable packages detection
- Safe package verification  
- Multiple package scenarios
- Version-specific vulnerability matching
- Network failure handling
- Edge cases and error conditions

## Development

### Building from Source

```bash
git clone https://github.com/bun-security-scanner/osv.git
cd osv
bun install
bun run build
```

### Contributing

We do not accept pull requests as this package is actively maintained. However, we appreciate if developers report bugs or suggest features by [opening an issue](https://github.com/bun-security-scanner/osv/issues/new).

See [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

## API Reference

### OSV.dev Integration

This scanner integrates with the following OSV.dev endpoints:

- **POST /v1/querybatch**: Batch vulnerability queries for multiple packages
- **POST /v1/query**: Individual package queries with pagination support

For complete OSV.dev API documentation, visit: https://google.github.io/osv.dev/api/

### Configuration Reference

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `OSV_LOG_LEVEL` | `info` | Logging level: debug, info, warn, error |
| `OSV_API_BASE_URL` | `https://api.osv.dev/v1` | OSV API base URL |
| `OSV_TIMEOUT_MS` | `30000` | Request timeout in milliseconds |
| `OSV_DISABLE_BATCH` | `false` | Disable batch queries (use individual queries) |

## Troubleshooting

### Common Issues

**Scanner not running during installation?**
- Verify `bunfig.toml` configuration
- Check that the package is installed as a dev dependency
- Enable debug logging: `OSV_LOG_LEVEL=debug bun install`

**Network timeouts?**
- Increase timeout: `OSV_TIMEOUT_MS=60000`
- Check internet connectivity to osv.dev
- Consider corporate firewall restrictions

**Too many false positives?**
- OSV.dev data is authoritative - verify vulnerabilities manually
- Check if you're using an outdated package version
- Report false positives to the OSV.dev project

### Debug Mode

Enable comprehensive debug output:

```bash
OSV_LOG_LEVEL=debug bun install your-package
```

This shows:
- Package deduplication statistics
- API request/response details  
- Vulnerability matching decisions
- Performance timing information

## License

MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **OSV.dev Team**: For maintaining the comprehensive vulnerability database
- **Bun Team**: For the innovative Security Scanner API

## Related Projects

- [Bun Security Scanner API](https://bun.com/docs/install/security-scanner-api)
- [OSV.dev](https://osv.dev/) - Open Source Vulnerabilities database

---

**Last Updated**: November 6, 2025
**Version**: 1.0.0

*This documentation is a living document and will be updated as the project evolves and new features are added.*