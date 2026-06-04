# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities via GitHub's private security disclosure:
[Security Advisories](https://github.com/Victorthedev/driftfinder/security/advisories/new)

Or email: ubahakweemeka@gmail.com with subject `[SECURITY] DriftFinder`.

**Response commitments:**
- Acknowledge within 72 hours
- Provide a fix timeline within 7 days of acknowledgement
- Patch CRITICAL vulnerabilities within 30 days

## Scope

DriftFinder is a read-only tool. It never modifies AWS resources, stores credentials,
or transmits data outside your AWS account. The attack surface is:
- Local config file parsing (YAML injection)
- State file parsing (Terraform/Pulumi JSON, CloudFormation YAML)
- AWS API responses (malformed response handling)
