# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.4.x   | :white_check_mark: |
| < 1.4   | :x:                |

Versions before 1.4.0 let plugin hooks run outside the sandbox and accepted plugin paths outside the
`Plugins` folder. Update to 1.4.0 or later.

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please bring it to our attention.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please use GitHub's private vulnerability reporting: [Report a vulnerability](https://github.com/damdavidprieto/ArgosCCF/security/advisories/new).

You can expect an initial response within a few days. If you do not hear back, please add a note to your private report.

## Security Features

See [Docs/Security.md](Docs/Security.md) for details and a checklist. In short:

*   **Secret redaction**: keyword- and entropy-based redaction of messages and data before they are logged.
*   **Log integrity**: one entry per line (line breaks cannot forge entries), no terminal escape sequences, and log files that cannot leave the Logs folder.
*   **Path checks**: configuration, preset and plugin names and the Logs override cannot point outside their folders.
*   **Plugin signatures**: optional requirement of a valid Authenticode signature, checked on the exact bytes that run.
*   **Sandboxing**: optional restricted runspace in Constrained Language Mode for plugins and their hooks. It reduces what a plugin can do but is not a security boundary without WDAC or AppLocker.
