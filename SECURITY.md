<!--
Copyright (c) 2025 maloma7. All rights reserved.
SPDX-License-Identifier: MIT
-->

# Security Policy

## Overview

The Bun OSV Scanner is a security-critical component that protects developers from installing vulnerable npm packages. This document outlines our security practices, threat model, and vulnerability reporting procedures.

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Security Architecture

### Threat Model

The Bun OSV Scanner operates in a security-sensitive environment and faces several potential threats:

#### **1. Supply Chain Attacks**
- **Threat**: Malicious actors compromising OSV.dev API responses
- **Mitigation**: 
  - HTTPS-only communication with OSV.dev
  - Response validation using Zod schemas
  - Fail-safe behavior on malformed responses

#### **2. API Manipulation Attacks**
- **Threat**: Man-in-the-middle attacks on OSV API calls
- **Mitigation**: 
  - Certificate pinning through HTTPS
  - Request/response integrity validation
  - No sensitive data transmitted to external APIs

#### **3. Data Injection Attacks**
- **Threat**: Malicious package names or versions causing code injection
- **Mitigation**: 
  - All package names/versions are treated as data, never executed
  - TypeScript strict mode prevents type confusion
  - Input sanitization for logging outputs

#### **4. Denial of Service (DoS)**
- **Threat**: API rate limiting or resource exhaustion
- **Mitigation**: 
  - Configurable request timeouts (30s default)
  - Exponential backoff retry logic
  - Fail-safe behavior (allow installation on scanner errors)
  - Batch query optimization to reduce API calls

#### **5. Information Disclosure**
- **Threat**: Sensitive data leakage through logs or errors
- **Mitigation**: 
  - Structured logging with configurable levels
  - No credentials or sensitive data in logs
  - Error messages provide minimal information disclosure

### Security Design Principles

#### **1. Fail-Safe Behavior**
The scanner is designed to **never block legitimate installations** due to scanner failures:

```typescript
} catch (error) {
    logger.error("OSV scanner encountered an unexpected error", { error: message });
    // Fail-safe: allow installation to proceed on scanner errors
    return [];
}
```

**Rationale**: Developer productivity must not be compromised by scanner infrastructure failures.

#### **2. Defense in Depth**
Multiple layers of security controls:

- **Input Validation**: Zod schema validation for all API responses
- **Network Security**: HTTPS-only, timeout controls, retry logic
- **Error Handling**: Graceful degradation with comprehensive error logging
- **Type Safety**: Full TypeScript coverage with strict compilation

#### **3. Principle of Least Privilege**
- Scanner operates with minimal permissions
- No file system write access required
- Read-only access to package information
- No external network access beyond OSV.dev API

#### **4. Transparency**
- All vulnerability data sourced from public OSV.dev database
- Open source implementation allows security review
- Comprehensive logging for audit trails

## Security Features

### **Input Validation**
All external data is validated using Zod schemas:

```typescript
// OSV API responses validated against strict schemas
const parsed = OSVBatchResponseSchema.parse(data);
const vulnerability = OSVVulnerabilitySchema.parse(data);
```

### **Network Security**
- **HTTPS Enforcement**: All OSV.dev API calls use HTTPS
- **Request Timeouts**: 30-second default timeout prevents hanging
- **Retry Logic**: Exponential backoff with smart retry conditions
- **User Agent**: Identifies scanner for OSV.dev monitoring

### **Error Handling**
- **Fail-Safe**: Scanner errors never block installations
- **Graceful Degradation**: Partial failures handled appropriately
- **Comprehensive Logging**: Full error context for debugging

### **Data Privacy**
- **No Sensitive Data**: Only package names/versions (public data) transmitted
- **No Local Storage**: No persistent data storage
- **Minimal Logging**: Only essential information logged

## Configuration Security

### Environment Variables
The scanner supports security-relevant environment variables:

```bash
# Logging configuration
OSV_LOG_LEVEL=info          # Controls information disclosure in logs

# Network security
OSV_TIMEOUT_MS=30000        # Prevents long-running requests
OSV_API_BASE_URL=...        # Allows custom OSV instances (enterprise)
OSV_DISABLE_BATCH=false     # Performance vs. security tradeoff
```

### Secure Defaults
- Default timeout: 30 seconds (prevents DoS)
- Default log level: `info` (balances security and debugging)
- HTTPS enforcement (no HTTP fallback)
- Batch queries enabled (reduces API surface)

## Vulnerability Assessment

### Regular Security Practices

#### **1. Dependency Management**
- Minimal dependency footprint (only Zod for runtime)
- Regular security audits of dependencies
- Automated dependency updates through Dependabot

#### **2. Code Security**
- TypeScript strict mode enabled
- Comprehensive linting with security rules
- No `eval()` or dynamic code execution
- Input sanitization for all external data

#### **3. Testing**
- Comprehensive test suite including security scenarios
- Edge case testing for malformed API responses
- Network failure simulation tests

### Known Security Considerations

#### **1. OSV.dev API Trust**
- **Risk**: Scanner depends on OSV.dev infrastructure integrity
- **Mitigation**: OSV.dev is Google-operated, industry-standard vulnerability database
- **Residual Risk**: Acceptable for most use cases

#### **2. Network Connectivity**
- **Risk**: Scanner requires internet access to function
- **Mitigation**: Fail-safe behavior allows offline development
- **Enterprise**: Custom OSV_API_BASE_URL for internal vulnerability databases

#### **3. Rate Limiting**
- **Risk**: OSV.dev may rate-limit high-volume usage
- **Mitigation**: Exponential backoff, batch queries, reasonable timeouts

## Reporting a Vulnerability

### Supported Languages
- English

### Reporting Process

#### **1. Initial Report**
Please report security vulnerabilities using **GitHub Security Advisories** at:
https://github.com/bun-security-scanner/osv/security/advisories/new

Include the following information in your report:
- **Impact Assessment**: Critical/High/Medium/Low
- **Vulnerability Type**: Code execution, data disclosure, DoS, etc.
- **Affected Versions**: Specific versions affected
- **Proof of Concept**: Steps to reproduce (if applicable)
- **Suggested Mitigation**: Your recommended fix (optional)

#### **2. Response Timeline**
- **Initial Response**: Within 3 days
- **Impact Assessment**: Within 7 days  
- **Security Fix**: Within 14 days for critical, 30 days for others
- **Public Disclosure**: 90 days after fix release

#### **3. Disclosure Policy**
We follow **responsible disclosure**:

1. **Private Report**: Initial vulnerability report kept confidential
2. **Coordinated Fix**: We work with reporter to develop fix
3. **Security Release**: Fixed version released with security advisory
4. **Public Disclosure**: Full details published after fix deployment

### What Qualifies as a Security Vulnerability

#### **In Scope**
- Code execution vulnerabilities
- Authentication/authorization bypasses  
- Data disclosure or privacy violations
- Denial of service attacks
- Supply chain attack vectors
- Cryptographic weaknesses

#### **Out of Scope**
- Issues in dependencies (report to upstream)
- Social engineering attacks
- Physical security issues
- Issues in OSV.dev infrastructure (report to Google)
- Performance issues without security impact

## Security Hardening Guide

### For Users

#### **1. Environment Security**
```bash
# Use minimal logging in production
OSV_LOG_LEVEL=warn

# Configure appropriate timeouts for your network
OSV_TIMEOUT_MS=30000

# Use HTTPS-only custom endpoints (enterprise)
OSV_API_BASE_URL=https://your-internal-osv.company.com/v1
```

#### **2. Network Security**
- Ensure HTTPS connectivity to api.osv.dev
- Configure corporate firewalls to allow OSV.dev access
- Consider proxy/VPN requirements for enterprise environments

#### **3. Monitoring**
- Monitor scanner logs for unusual patterns
- Set up alerts for repeated scanner failures
- Track vulnerability detection rates

### For Developers

#### **1. Development Environment**
```bash
# Enable debug logging for development
OSV_LOG_LEVEL=debug

# Use shorter timeouts for faster feedback
OSV_TIMEOUT_MS=10000
```

#### **2. Testing**
```bash
# Test with known vulnerable packages
bun run src/cli.ts test event-stream@3.3.6

# Test network failure handling
OSV_API_BASE_URL=https://invalid.example.com bun test
```

## Incident Response

### In Case of Security Incident

#### **1. Immediate Actions**
- Assess impact and scope
- Disable scanner if necessary (set empty scanner in bunfig.toml)
- Notify security team
- Begin incident documentation

#### **2. Investigation**
- Collect relevant logs and evidence
- Determine root cause
- Assess data exposure risk
- Document timeline

#### **3. Remediation**
- Apply security fix
- Update to latest secure version
- Review and update security practices
- Communicate with stakeholders

## Compliance and Standards

### Security Standards
- **OWASP Top 10**: Address common web application security risks
- **NIST Cybersecurity Framework**: Identify, Protect, Detect, Respond, Recover
- **Supply Chain Security**: SLSA (Supply chain Levels for Software Artifacts) principles

### Audit Trail
- All security-relevant events logged with timestamps
- Vulnerability detection events recorded
- Configuration changes logged
- API interactions tracked

## Contact Information

- **Security Vulnerabilities**: https://github.com/bun-security-scanner/osv/security/advisories/new
- **General Issues**: https://github.com/bun-security-scanner/osv/issues
- **Security Advisories**: https://github.com/bun-security-scanner/osv/security

---

**Last Updated**: September 12, 2025  
**Version**: 1.0.0

*This security policy is a living document and will be updated as the project evolves and new security considerations emerge.*