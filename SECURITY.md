# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Issuerd, please report it privately.

- **Email:** security@issuerd.org
- **Process:** Please do not open public issues for security bugs. Provide a detailed description and reproduction steps, and allow reasonable time for remediation before public disclosure.

## Supported Versions

Security fixes are applied to the latest release line. We recommend always running the most recent release.

| Version   | Supported |
|-----------|-----------|
| latest    | yes       |
| older     | no        |

## Scope

Issuerd is an identity and access management server: it issues and validates tokens, stores credentials, and federates against external directories. Reports are especially welcome for:

- Authentication or authorization bypass (any flow, grant, or realm boundary)
- Token validation weaknesses (signature, expiry, audience, DPoP binding, replay)
- Credential handling (passwords, TOTP secrets, WebAuthn, signing keys at rest or in transit)
- Cross-realm isolation failures
- Injection and SSRF in federation (LDAP/Kerberos) and identity brokering paths
- Information disclosure through logs, error responses, or the discovery document

## What to Expect

- An acknowledgment of your report within a few days.
- A triage decision and, if accepted, a fix developed privately and shipped in a release.
- Credit in the release notes if you want it (name or handle of your choice), once the fix is public.

## Hardening Documentation

Operational security guidance (TLS, brute-force protection, signing-key encryption at rest, CORS lockdown) lives in [docs/security.md](docs/security.md).
