# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.2.0] - 2026-11-26

### Added
- **Anchors of your own**: `Write-CCFAnchor` writes "<kind> <text>" to the Application log with your source and event
  ID, and `Get-CCFAnchor` reads them by source, event ID, kind and time. Anchors other programs wrote in that format
  before are read as they are.
- `Set-CCFAnchorStore -Store Memory`: anchors go to memory instead of the event log, for tests.
- **Anchors per category**: `Register-CCFChainAnchor -Category` registers a target and an interval for some
  categories only; the registration without `-Category` covers the rest. `Save-CCFChainAnchor` anchors the current
  heads now, whatever the interval.
- **Chains of folders**: `Get-CCFFolderHash`, `Add-CCFFolderHash` (a chained line per folder in CCF_Folders.log)
  and `Test-CCFFolderChain` (the chain, folders changed, folders missing, and those deleted before `-KeepDays`).
  `Export-CCFEvidence -Folder -FolderLog` packs folders and compares them with their recorded hash.
- `Set-CCFRedactionOption -EncodedCommand Decode`: a PowerShell `-EncodedCommand` becomes its decoded text, with the
  secrets in it redacted, after the same fingerprint. The default is still the fingerprint alone.
- `New-CCFChainKey -Reader`: a key for logs written by several accounts, protected for the computer and readable
  only by those accounts, SYSTEM and Administrators.

### Changed
- Chain anchors written to the event log carry a key of the log's folder (format v2). `Get-CCFChainAnchor -Path`
  and `Test-CCFLogChain -EventLogSource` take only the anchors of that file, so a copy of the program in another
  folder does not cause false alarms. Version 1 anchors are still read, matched by file name.

### Fixed
- `net user ... /passwordreq:yes` and `/passwordchg:no` are no longer redacted: yes and no are not passwords.

## [2.1.0] - 2026-11-26

### Added
- **Signed chains.** `New-CCFChainKey` creates a key protected with Windows DPAPI for the current account, and
  `Initialize-CCFLogger -ChainKeyPath` signs every chained line with it (HMAC-SHA256, ` #mac=` instead of
  ` #chain=`). Without the key, whoever can write the file cannot add, change or rewrite lines unnoticed.
  `Test-CCFLogChain -ChainKeyPath` checks the signatures and reports `KeyedEntries`.
- `Test-CCFLogChain -EventLogSource` reads the anchors of the file from the event log itself, and
  `Test-CCFHealth -VerifyChain` checks every chained log of the session (identifier, key and anchors included).
- `Initialize-CCFLogger -WriterInfo` adds who wrote each line: account, elevation and process ID.
- `Test-CCFLogChain` returns `ClockWarnings`: lines dated earlier than the line before (`-ClockToleranceSeconds`).
- `Export-CCFEvidence` packs logs, their rotated copies, their anchors and the result of checking them into a zip,
  with the SHA-256 of every file, and returns the SHA-256 of the zip.
- `Initialize-CCFLogger -NoConsole`, for scheduled tasks and services.

### Changed
- **Faster writes.** Short texts are checked against all the built-in rules in one search, and the rules run only
  when one can match (the result is the same). Measured on Windows: an entry takes 3-4.5 ms instead of 5.5-6, and a
  chained audit record 5-8.5 ms instead of 13. The lock of each log file stays open, and the last hash is read from the last
  4 KB of the file first.
- **Fewer false positives, measured on the evidence of a hardening tool** (163 files, 69,000 lines: 683 values
  redacted without being secrets, now 2). Keys that describe a secret (`MinimumPasswordLength`, `PasswordLastSet`,
  `credential.helper`) and unquoted values that cannot be one (true, false, null, `{`, and code such as `$x = $y`)
  are kept; "signature" names a secret only at the end of a key (`x-amz-signature`, not
  `AntivirusSignatureVersion`); Windows session numbers (`SessionId : 1`) are kept. `Test-CCFEntropyContent`
  leaves alone command names, Store app packages and words joined to hexadecimal parts.
- `-EncodedCommand` is also recognized in command lines inside JSON (`pwsh.exe\" -EncodedCommand ...`).

### Fixed
- An unchained line that claims earlier lines were archived no longer excuses deleted lines in
  `Test-CCFLogChain -IncludeRotated`.
- `Remove-CCFOldLog` keeps the copies of a signed log when the session does not have its key, instead of
  recording their deletion without a signature.

## [2.0.0] - 2026-11-26

ArgosCCF is now only secure logging and redaction.

### Removed
- **Configuration**: `Get-CCFConfig`, `Set-CCFUserConfig`, `Merge-CCFConfig`, `Remove-CCFConfigCache`,
  `Test-CCFConfigSchema`, the `Configs` folder and the `Logging.DefaultPath` setting. Use `Initialize-CCFLogger -Path`
  to choose the logs folder.
- **Plugins**: `Get-CCFPlugin`, `Invoke-CCFPlugin`, `Confirm-CCFPluginSignature` and the `Plugins` folder.
- **Parallel execution**: `Invoke-CCFParallel`. Use `ForEach-Object -Parallel` or ThreadJob.
- `Submit-CCFHeartbeat`, which nothing read.
- **Aliases**: `Log-Info`, `Log-Success`, `Log-Warn`, `Log-Error`, `Log-Critical`, `Log-Debug`, `Log-Header`,
  `Log-Attack`, `Log-Audit`, `Init-CCFLogger`, `Catch-CCFError`, `Redact-CCFSensitiveData`, `Test-CCFHighEntropy`,
  `Remove-OldCCFLogs`, `Clear-CCFConfigCache`, `Test-CCFPluginSignature`, `Get-CCFPlugins`. Use the full command names.
- `Get-CCFPath` targets `Configs`, `Plugins`, `Tests` and `UserConfigs`.

### Added
- **`Register-CCFChainAnchor -EventLogSource`** writes every chain head to the Windows Application log, and
  **`Get-CCFChainAnchor`** reads them back for `Test-CCFLogChain -ExpectedLastHash`.
- `Test-CCFLogChain` returns `ExternalHashes`: how many hashes from outside the file were checked.

### Fixed
- **`Remove-CCFOldLog` no longer breaks a chained log.** It deleted any old file, including the current one or a copy
  in the middle of the chain. Now it deletes only the oldest rotated copies of a chained log, oldest first, and records
  them in the current file as rotation does.
- **A program running as administrator and the same program without elevation can write the same log files.** On
  Windows the write lock is created so that any account can open it, and a lock that cannot be opened no longer makes
  the entry fail: it is written without it.

## [1.7.0] - 2026-11-26

### Added
- **`Register-CCFChainAnchor`**: runs a script block with every new chain head (path, category, hash, identifier, time),
  to keep it where the log's writer cannot change it. Failures never stop logging; `Test-CCFHealth` reports them.
- **`-Strict`** on `Initialize-CCFLogger`, `Write-CCFLog`, `Write-CCFAuditRecord` and `Write-CCFSecurityRecord`: an entry
  that cannot be written throws an error instead of a warning.
- **Copies without the deprecated components**: the module loads when `Core/Configuration.ps1`, `Plugins.ps1` and
  `Execution.ps1` are left out, and exports the rest. `Test-CCFHealth` only checks the components present.
- **Secrets in sentences**: "the password is X" and "la contrasena es X" when X has a digit or a symbol, or is quoted.
- `Test-CCFLogChain -ExpectedLastHash` also takes objects with `Hash` and `Time`; the result has `ArchivedUntil` and
  `MissingHashes`.

### Fixed
- **Rotation no longer breaks a chained log.** When the oldest copy was deleted, `Test-CCFLogChain -IncludeRotated`
  reported the log as changed, and saved hashes of the deleted copy as missing. The new file now starts with a chained
  line that records the last hash and time of the deleted copy; the check starts from it, and saved hashes older than
  it are no longer required (with their time).
- `clave` only counts as a secret key in text when its value has a digit or a symbol, or is quoted.

## [1.6.0] - 2026-11-25

### Added
- **Secrets in command lines**: `-Password x`, `--token x`, `/pass:x` and similar parameters in any program, and the
  options of known programs: `net user`, `net use`, `rasdial`, `schtasks /rp` and other Windows tools, PsTools, `sqlcmd`,
  `mysql`, `curl -u`, container logins, `sshpass`, 7-Zip, RAR, `zip`, `openssl`, `certutil` and `netsh`. Short options
  such as `-p` are only read that way for programs where they carry a password.
- **`ConvertTo-SecureString` literals** and **XML elements** whose name is a secret.
- **Spanish keys**: `contrasena` (with or without the tilde), `clave` and `credencial`.
- **`-EncodedCommand` fingerprints**: the command becomes `[ENCODED 1a2b3c4d 120 chars]`, so a repeated command can be
  recognized without keeping it.
- **`Initialize-CCFLogger -ChainId`**, `Test-CCFLogChain -ChainId` and `Get-CCFLogChainHead -AsObject`: chained lines can
  carry who writes them, to tell another copy of a program from deleted lines.

### Fixed
- `secretary=...` and test results such as `pass=3 fail=0` are no longer redacted.
- The command table in the README lists the chain commands.

## [1.5.0] - 2026-11-22

### Added
- **Tamper-evident logs**: `Initialize-CCFLogger -Chain Audit, Security` ends every line of those categories with
  a SHA-256 of the line and of the previous hash (` #chain=<hex>`, or a `Chain` property in JSON mode). The
  hash is computed inside the file lock, so concurrent writers chain in write order, and it continues across
  rotation. Chained entries are always written directly, also with `-Background`.
- **`Test-CCFLogChain`**: finds a line that was changed, inserted or deleted (`-IncludeRotated` checks the
  rotated copies too). **`Get-CCFLogChainHead`** returns the last hash to keep elsewhere; with
  `Test-CCFLogChain -ExpectedLastHash` it also shows lines deleted from the end.

## [1.4.1] - 2026-11-22

### Security
- **`RequireSignedPlugins` can no longer be switched off from the user settings.** The configuration
  layers are merged and the last one wins, and the user layer lives in the data folder, which any
  program running as the user can write. Once any layer (factory, module or user settings) enables the
  check, a later layer cannot disable it; a layer that cannot be read counts as enabling it.

### Fixed
- **`Remove-CCFOldLog -CompressBeforeDelete` could delete logs that were never archived.** A failed
  `Compress-Archive` only wrote an error and the files were deleted anyway, and declining the
  compression with `-Confirm` still deleted them. Nothing is deleted now unless the archive was written.
- **Audit and Security entries that cannot be written warn on the console.** A failed write was only
  reported with `Write-Verbose`, so audit records could be lost without anyone noticing. Audit and
  Security entries, and errors, now produce a warning (also with the background writer).
- **`Invoke-CCFParallel`**: errors written with `Write-Error` count as failures instead of returning
  `Success`; an object whose runspace fails gets a `Failed` result instead of disappearing from the
  output; `Retries` is the number of retries made (it counted the attempts); the thread count in the
  log is the one actually used.
- **Plugin hooks declared as `function Before-Execute($Arguments)`** (parameters after the name)
  did not receive `-Arguments` or `-Result`.
- The help of `Protect-CCFSensitiveData` now says that an unquoted value ends at the first space,
  comma or semicolon.

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
- **Background writing** (optional): with `Initialize-CCFLogger -Background`, log files are written by a
  background worker, in order and in batches, with the same lock and rotation. `Write-CCFLog` takes
  about half the time (5.4 to 2.5 ms per entry on PowerShell 7, 5.3 to 2.4 ms on 5.1). ERROR and
  CRITICAL entries, Security and Audit records and `-NoBuffer` entries still wait until they are on
  disk; the queue (10,000 entries) makes callers wait when full instead of dropping entries; and it
  is written out when PowerShell exits, when the module is removed and on `Stop-CCFLogWriter`.
  `Get-CCFLogWriter` reports queued, written and failed entries, `Wait-CCFLogWriter` waits for the
  queue, and `Test-CCFHealth` checks the writer. `Write-CCFLog -NoBuffer` had no effect and now makes
  that entry wait.
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
  module exports its functions (40 in this version) and 17 aliases.
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
- **Concurrent writes lost entries**: runspaces or processes logging to the same file at the same time
  collided on the file and the failed writes were dropped silently (in a test, 428 of 2,000 entries
  from 8 runspaces and 391 of 750 from 3 processes arrived). Each write now locks the file with a
  named mutex and retries briefly when the file is in use; the same test keeps every entry.
- **Rotation only at start**: `-MaxMB` was checked only when `Initialize-CCFLogger` ran, so a long
  session grew past it, and category files (`CCF_Security.log`, `CCF_Audit.log`...) never rotated.
  The size is now checked before every write, for every file.
- **Parallel start-up**: runspaces that started the logger, or imported the module, at the same time
  wrote the same probe file to check that the logs folder was writable, collided and reported it as
  read-only (`Initialize-CCFLogger -Path` then threw). Each check now uses its own file.
- **One-item arrays** in hashtables and objects lost their array shape when redacted.
- **False positives**: GUIDs, Windows SIDs, hexadecimal hashes and certificate thumbprints were
  redacted as random-looking secrets, which removed useful values from audit logs. They are kept now,
  and so are identifiers such as `Win32_OperatingSystem` and long kebab-case names.
- **Windows PowerShell 5.1**: source files with non-ASCII characters are saved as UTF-8 with BOM.
- Removed a debug line that printed the log target on every write.

### Changed
- `Initialize-CCFLogger -JsonOutput` writes one JSON object per line.
- Log files are written as UTF-8 without BOM on every PowerShell version (Windows PowerShell 5.1
  added a BOM to new files).
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
