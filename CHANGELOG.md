# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
