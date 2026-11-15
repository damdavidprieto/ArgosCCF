# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.4.0] - 2026-11-14

ArgosCCF is now a secure logging module: secrets are redacted before anything is written. The
configuration, plugin and parallel execution commands keep working but are deprecated.

### Added
- **Redaction of known formats**: connection strings (values with spaces included), credentials in
  URLs, `Authorization` and `Proxy-Authorization` headers (the scheme is kept), bearer tokens, PEM
  private key blocks, JSON web tokens, and GitHub, AWS access key ID, Slack, Stripe, Google API, npm
  and `sk-` keys. Key/value pairs are also recognized in JSON (`"password": "..."`), with quoted values
  that contain spaces, and inside longer keys (`db_password`, `ClientSecret`, `x-api-key`).
- `Register-CCFSecret` and `Unregister-CCFSecret`: values (or the password of a `PSCredential` or a
  `SecureString`) that are redacted wherever they appear, in any format, with their URL-encoded form.
- `Register-CCFRedactionPattern`, `Unregister-CCFRedactionPattern` and `Get-CCFRedactionPattern`:
  your own regular expressions, and the list of every rule in the order it is applied.
- `Protect-CCFLogFile`: writes a redacted copy of a transcript or of a log written by another tool,
  line by line, including private key blocks that span several lines.
- `Protect-CCFSensitiveData` accepts pipeline input and arrays, so it can sit in front of any other
  logger (for example `Write-PSFMessage`).
- `Initialize-CCFLogger -Path`: the folder for this session's logs, such as the script's own folder.
- `Get-CCFPath -Target Data` and `-Target UserConfigs`.

### Deprecated
- Configuration (`Get-CCFConfig`, `Set-CCFUserConfig`, `Merge-CCFConfig`, `Test-CCFConfigSchema`,
  `Remove-CCFConfigCache`), plugins (`Get-CCFPlugin`, `Invoke-CCFPlugin`,
  `Confirm-CCFPluginSignature`) and `Invoke-CCFParallel`. They keep working in 1.x and will be removed
  in 2.0.0. The help and the README name alternatives.

### Security
- **Redaction fails closed**: every rule has a 500 ms time limit per text. If a rule runs out of time
  or fails, the whole text is replaced instead of being written unchecked. Text of 2,000 characters
  or more used to skip the check for random-looking secrets; it no longer does.
- **Secrets that were written in clear**: JSON values (`{"password":"..."}`), quoted values with
  spaces, `Authorization: Basic ...`, credentials in URLs, connection string passwords with spaces,
  AWS access key IDs and private key blocks. A probe of 16 common cases found 7 that leaked; all 16
  are now redacted.
- **Objects**: `PSCredential`, `NetworkCredential` and `SecureString` values in log data are redacted,
  arrays are checked item by item, and other objects are written as their redacted text form instead
  of being serialized with all their properties.
- **Log files outside the Logs folder.** `Write-CCFLog -Category` and `Initialize-CCFLogger -FileName`
  became part of a file path without checks, so a value such as `..\..\x` wrote outside `Logs`. They now
  accept only letters, digits, `.`, `-` and `_`.
- **Log forging and terminal escapes.** Messages were written as-is, so a line break could add a fake
  entry to a log file and an ANSI sequence could restyle or hide console output. Each entry is now one
  line (line breaks are written as `\n`) and control characters are removed.
- **Configuration names.** `Set-CCFUserConfig` and preset names were not validated, so a name such as
  `..\..\x` wrote or read JSON outside `Configs`. Both now use the same check as `Get-CCFConfig`.
- **Logs override.** `Logging.DefaultPath` was compared as a text prefix, so `..` segments could point
  it outside the allowed folder. The path is now resolved before the check.
- **Plugin signature check.** The signature was checked on the file and the file was then read again
  to run it; now both use the same bytes, so the plugin cannot be swapped in between.
- **Plugin hooks escaped the sandbox**: with `-HardenedMode` only the plugin's main code ran in the
  restricted runspace; its `Before-Execute` and `After-Execute` hooks ran in the caller's session with
  full language. Hooks now run in the same restricted runspace.
- **Plugin folder check**: `Invoke-CCFPlugin` compared the raw path as a text prefix, so
  `Plugins\..\file.ps1` and sibling folders such as `PluginsX` passed. The path is now normalized, must
  be inside `Plugins` and must be an existing `.ps1` file.
- Documented that Constrained Language Mode is not a security boundary without WDAC or AppLocker.

### Fixed
- **Exports**: the Core files were imported as separate global modules (`Logging`, `Configuration`,
  `Plugins`, `Execution`), so `Get-Command -Module ArgosCCF` listed only 2 functions and those generic
  module names could clash with other modules. They are now loaded into ArgosCCF's own scope and the
  module exports its functions (37 in this version) and 17 aliases.
- **Missing functions**: `Write-CCFSecurityRecord`, `Write-CCFAuditRecord` and the aliases `Log-Attack`,
  `Log-Audit`, `Test-CCFHighEntropy` were documented and listed in the manifest but did not exist.
  Added, together with `Remove-CCFOldLog` (alias `Remove-OldCCFLogs`). `Merge-CCFConfig`,
  `Set-CCFLogLevel` and `Confirm-CCFPluginSignature` are now exported.
- **Redaction**: `Protect-CCFSensitiveData` returned `PSCustomObject` input as a plain string instead of
  redacting it, and did not mark values beyond the depth limit (`[DEPTH-LIMIT]`).
- **Parallel execution**: `Invoke-CCFParallel` returned results in completion order and leaked internal
  `PowerShell` objects into its output; results now come back in input order.
- **Plugins**: hooks (`Before-Execute`, `After-Execute`) were loaded by dot-sourcing the plugin, which ran
  its main code twice; they are now read from the script's syntax tree. Sandboxed runs also leaked a
  `PowerShell` object into the result and now dispose their runspace.
- **All-users installs**: importing the module threw when it could not create `Logs` inside a read-only
  module folder (such as `Program Files`).
- **Logs and user settings were lost on every update**: they were saved inside the versioned folder the
  module is installed in, so `Update-Module` started with none and `Uninstall-Module` deleted them.
  They are now kept in a per-user data folder (`ArgosCCF` under `%LOCALAPPDATA%`, `$XDG_DATA_HOME` or
  `~/.local/share`, or `$env:CCF_DATA_PATH`) and ArgosCCF no longer writes into its own folder. User
  settings saved next to the module by earlier versions are still read.
- **One-item arrays** in hashtables and objects lost their array shape when redacted.
- **False positives**: GUIDs, Windows SIDs, hexadecimal hashes and certificate thumbprints were
  redacted as random-looking secrets, which removed useful values from audit logs. They are kept now,
  and so are identifiers such as `Win32_OperatingSystem` and long kebab-case names.
- **Windows PowerShell 5.1**: source files with non-ASCII characters are saved as UTF-8 with BOM.
- Removed a debug line that printed the log target on every write.

### Changed
- `Initialize-CCFLogger -JsonOutput` writes one JSON object per line.
- The level shortcuts (`Write-CCFLogInfo`, ...) have named `-Message` and `-Data` parameters; the
  positional form still works.
- Paths use forward slashes, so configuration loading works on Linux and macOS.
- Tests: the demo scripts in `Tests/Integration` and `Tests/E2E` (which logged results instead of
  asserting them) were replaced by Pester tests. 52 tests, run in CI on Windows, Linux and macOS
  (PowerShell 7) and on Windows PowerShell 5.1.
- Packaging: `build.ps1` builds `output/ArgosCCF` with only the runtime files, and the `Publish`
  workflow publishes that folder. Version 1.3.0 had been packed from the repository root and included
  `.git`, tests, docs and test plugins. Removed `ArgosCCF.nuspec`, `Core/diagnostic.ps1` and the test
  plugins from `Plugins/`.
- Removed the self-assessed audit reports from `Docs/`.
- Log and error messages are in English (they were in Spanish), and security blocks start with
  `SECURITY BLOCK:`. Scripts that matched the old Spanish texts need updating.
- `Get-CCFPlugins` is now `Get-CCFPlugin` (singular noun); the old name remains as an alias.
  It now also finds plugins in subfolders of `Plugins`, such as the shipped `Plugins/Examples`.
- `Set-CCFUserConfig` supports `-WhatIf` and `-Confirm`; `Set-CCFLogLevel -Level` is mandatory.
- Configuration and plugin manifest files are read and written as UTF-8 on Windows PowerShell 5.1.
- Log timestamps are in UTC (they already ended in `Z`), and the host name comes from
  `[Environment]::MachineName`, which also works on Linux and macOS.
- `Invoke-CCFParallel` uses the processor count on every platform (it read a Windows-only variable).
- The configuration cache keeps results for different preset lists apart.
- `Test-CCFEntropyContent` requires upper case, lower case and digits with no run of more than six
  lower case letters (or, from 32 characters, two of those kinds with at least one digit in five), so
  ordinary words and identifiers are not redacted.
- `Logging.DefaultPath` in `ccf_core` is now relative to, and must stay inside, the data folder (it was
  the module folder).
- The module description, tags and README describe ArgosCCF as a secure logging module.
- `Plugins/Examples/SystemInfo.ps1` works on Linux and macOS and returns its data instead of printing it.
- `Configs/Factory/ccf_core.json` lists only the settings the module reads
  (`Logging.DefaultPath`, `Security.RequireSignedPlugins`); the example configurations
  `demo_app.json` and `verify.json` are no longer shipped.
- Every exported command has complete help, and `Docs/API-Reference.md` is generated from it.
- Build and CI follow the structure of the Sampler module template: `PSScriptAnalyzerSettings.psd1`
  (with Windows PowerShell 5.1 compatibility rules), QA tests for help, analyzer, changelog and
  manifest, and a `Publish` workflow that also creates the GitHub release.
- New examples in `Examples/` that run as part of the tests and clean up after themselves.

## [1.3.0] - 2026-01-21

### 💎 Professional Grade Refactoring (Fase 5)
#### [ENG]
- **API Standardization**: Renamed core functions to Microsoft-approved verbs (`Write-CCFLog*`, `Initialize-CCFLogger`, `Protect-CCFSensitiveData`, `Confirm-CCFPluginSignature`).
- **Backward Compatibility**: Implemented a comprehensive **Alias System** (15+ aliases) ensures zero breaking changes for existing scripts.
- **Zero-Noise Quality**: Resolved all PSScriptAnalyzer warnings and implemented strong typing across all core parameters.
- **Resilience Engine**: Added `Test-CCFHealth` API and LogProvider Heartbeat monitoring.
- **Performance Fine-Tuning**: Migrated Configuration cache to `ConcurrentDictionary` for thread-safety and implemented Path Memoization to reduce I/O overhead.

#### [ESP]
- **Estandarización de API**: Renombrado de funciones nucleares a verbos aprobados por Microsoft (`Write-CCFLog*`, `Initialize-CCFLogger`, `Protect-CCFSensitiveData`, `Confirm-CCFPluginSignature`).
- **Retrocompatibilidad**: Implementado un **Sistema de Alias** exhaustivo (15+ alias) que garantiza cero cambios disruptivos en scripts existentes.
- **Calidad Zero-Noise**: Resueltas todas las advertencias de PSScriptAnalyzer e implementado tipado fuerte en todos los parámetros core.
- **Motor de Resiliencia**: Añadida la API `Test-CCFHealth` y monitorización de latido (Heartbeat) del LogProvider.
- **Optimización de Rendimiento**: Migrada la caché de configuración a `ConcurrentDictionary` (thread-safe) e implementada memoización de rutas para reducir latencia de I/O.

### Added
- **ArgosCCF Rebranding**: Project renamed from CCF to ArgosCCF.
- **Parallel Execution Engine**: `Invoke-CCFParallel` for high-performance multi-threading.
- **Plugin Signature Verification**: Enforce authenticode signatures for plugins.
- **System Hardening**: Enhanced L5 validation across all core modules.
- **Entropy Sanitization**: Improved secret detection in logs via `Test-CCFEntropyContent`.

### Changed
- Directory structure refactored to standard PowerShell module layout.
- `Get-CCFPath` optimized for security and environment discovery.
- Logging engine now supports dynamic providers with fallback security.

## [1.2.0] - 2025-12-15

### Added
- Security hardening (L3/L4) for file operations.
- Initial Plugin system with basic hooks.

### Fixed
- Log rotation issues on Windows Server.

## [1.0.0] - 2025-06-01

### Added
- Initial release of Cassiel Core Foundation.
- Basic logging and configuration management.
