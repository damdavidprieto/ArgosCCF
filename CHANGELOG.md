# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-11-13

### Fixed
- **Exports**: the Core files were imported as separate global modules (`Logging`, `Configuration`,
  `Plugins`, `Execution`), so `Get-Command -Module ArgosCCF` listed only 2 functions and those generic
  module names could clash with other modules. They are now loaded into ArgosCCF's own scope and the
  module exports its 31 functions and 16 aliases.
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
  module folder (such as `Program Files`). Logs now fall back to a per-user folder.
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
