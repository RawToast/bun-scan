# Bun-Scan

A security scanner for [Bun](https://bun.sh/) that checks packages for known vulnerabilities during installation.

## Features

- **Real-time Scanning**: Checks packages against configured sources (OSV, npm, or both) during installation
- **Whitelists**: Specific warnings can be ignored
- **Fail-safe**: Can configure non-critical advisories to not prevent installations

## Installation

```bash
# Install as a dev dependency
bun add -d bun-scan
```

Add to your `bunfig.toml`:

```toml
[install.security]
scanner = "bun-scan"
```

Select your source from `npm`, `osv` (default), or run checks against `both`

Note to set the schema version in the URL to the correct version:

```json
{
  "$schema": "https://raw.githubusercontent.com/rawtoast/bun-scan/master/v1.1.0/bun-scan.schema.json",
  "source": "npm"
}
```

### Ignoring Vulnerabilities

A package may have a vulnerability, but your project is not affected. In this scenario, you would
not want installations to be prevented. To work around this, the vulnerability can be flagged as ignored in your `bun-scan.config.json`

```json
{
  "$schema": "https://raw.githubusercontent.com/rawtoast/bun-scan/master/v1.1.0/bun-scan.schema.json",
  "source": "npm",
  "packages": {
    "hono": {
      "vulnerabilities": ["CVE-2026-22818"],
      "reason": "Project does not use JWT from hono, verify again in June",
      "until": "2026-06-01"
    }
  }
}
```

Note that `bunReportWarnings` can be set `false` to print warning-level advisories without triggering Bun's install prompt:

```json
{
  "bunReportWarnings": false
}
```

### Advisory Levels

#### Fatal (Installation Blocked)

- **CVSS Score**: ≥ 7.0 (High/Critical)
- **Database Severity**: CRITICAL or HIGH
- **Action**: Installation is immediately blocked

#### Warning (User Prompted)

- **CVSS Score**: < 7.0 (Medium/Low)
- **Database Severity**: MEDIUM, LOW, or unspecified
- **Action**: User is prompted to continue or cancel

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
