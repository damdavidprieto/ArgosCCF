# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.3.x   | :white_check_mark: |
| 1.2.x   | :white_check_mark: |
| < 1.2   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please bring it to our attention.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to `32666182+damdavidprieto@users.noreply.github.com` (Placeholder - confirm contact info).

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

## Security Features

ArgosCCF includes several mechanisms to ensure secure automation:

*   **L5 Hardening**: Strict validation of input types and boundaries.
*   **Plugin Signtures**: Execution policies that can require cryptographically signed plugins.
*   **Sandboxing**: Configurable Constrained Language Mode for untrusted plugins.
*   **Secret Redaction**: Automatic entropy-based detection and redaction of secrets in logs.
*   **Anti-Path Traversal**: Strict validation of file paths to prevent unauthorized file system access.
