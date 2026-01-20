# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-01-20

### Added
- **ArgosCCF Rebranding**: Project renamed from CCF to ArgosCCF.
- **Parallel Execution Engine**: `Invoke-CCFParallel` for high-performance multi-threading.
- **Plugin Signature Verification**: Enforce authenticode signatures for plugins.
- **System Hardening**: Enhanced L5 validation across all core modules.
- **Entropy Sanitization**: Improved secret detection in logs.

### Changed
- Directory structure refactored to standard PowerShell module layout.
- `Get-CCFPath` optimized for security.
- Logging engine now supports dynamic providers.

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
