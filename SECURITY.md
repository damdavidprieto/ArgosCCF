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

Instead, please use GitHub's private vulnerability reporting: [Report a vulnerability](https://github.com/damdavidprieto/ArgosCCF/security/advisories/new).

You can expect an initial response within a few days. If you do not hear back, please add a note to your private report.

## Security Features

ArgosCCF includes several mechanisms to ensure secure automation:

*   **L5 Hardening**: Strict validation of input types and boundaries.
*   **Plugin Signtures**: Execution policies that can require cryptographically signed plugins.
*   **Sandboxing**: Configurable Constrained Language Mode for untrusted plugins.
*   **Secret Redaction**: Automatic entropy-based detection and redaction of secrets in logs.
*   **Anti-Path Traversal**: Strict validation of file paths to prevent unauthorized file system access.
