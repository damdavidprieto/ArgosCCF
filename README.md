# ArgosCCF

[![CI](https://github.com/damdavidprieto/ArgosCCF/actions/workflows/ci.yml/badge.svg)](https://github.com/damdavidprieto/ArgosCCF/actions/workflows/ci.yml)
[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/ArgosCCF.svg)](https://www.powershellgallery.com/packages/ArgosCCF)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Building blocks for PowerShell automation scripts:

- **Logging** to the console, files and your own providers, with secret redaction, security and
  audit records, rotation and clean-up. One entry is always one line: messages cannot forge entries.
- **Layered JSON configuration**: factory defaults, presets and user overrides, merged and cached.
- **Plugins** that run only from the `Plugins` folder, with optional Authenticode signature checks
  and an optional restricted runspace.
- **Parallel execution** in runspace pools, with retries and results in input order.

Windows PowerShell 5.1 and PowerShell 7+ on Windows, Linux and macOS. No dependencies. Every command
has full help: `Get-Help Invoke-CCFParallel -Full`.

## Installation

```powershell
Install-Module -Name ArgosCCF -Scope CurrentUser
```

The module loads automatically the first time you call one of its commands.

## Quick start

```powershell
Initialize-CCFLogger -FileName 'Backup.log'
Write-CCFLogInfo 'Backup started'
Write-CCFLog -Message 'Connecting with password=Secr3t!' -Level INFO   # written as password=[REDACTED]
Write-CCFAuditRecord -Action 'Backup' -User $env:USERNAME -Resource 'D:\Data'

$config = Get-CCFConfig -ConfigName 'ccf_core'

$results = Invoke-CCFParallel -InputObjects 'web01', 'web02', 'db01' -MaxThreads 3 -ScriptBlock {
    param($server)
    Test-Connection -ComputerName $server -Count 1 -Quiet
}
$results | Format-Table Target, Status, Output
```

Logs go to the module's `Logs` folder or, when that folder is read-only (for example after an
all-users install), to `%LOCALAPPDATA%\ArgosCCF\Logs` (`~/.local/share/ArgosCCF/Logs` on Linux and
macOS). `Get-CCFPath -Target Logs` shows where.

More in [`Examples/`](Examples/): logging, configuration layers, plugins and parallel execution.
Each example runs as part of the tests.

## Commands

| Area | Commands |
|---|---|
| Logging | `Initialize-CCFLogger`, `Write-CCFLog`, `Write-CCFLogInfo`, `Write-CCFLogSuccess`, `Write-CCFLogWarn`, `Write-CCFLogError`, `Write-CCFLogCritical`, `Write-CCFLogDebug`, `Write-CCFLogHeader`, `Set-CCFLogLevel`, `Register-CCFLogProvider`, `Register-CCFSIEMProvider` |
| Security and audit | `Write-CCFSecurityRecord`, `Write-CCFAuditRecord`, `Write-CCFErrorRecord`, `Protect-CCFSensitiveData`, `Test-CCFEntropyContent`, `Remove-CCFOldLog` |
| Configuration | `Get-CCFConfig`, `Set-CCFUserConfig`, `Merge-CCFConfig`, `Test-CCFConfigSchema`, `Remove-CCFConfigCache` |
| Plugins | `Get-CCFPlugin`, `Invoke-CCFPlugin`, `Confirm-CCFPluginSignature` |
| Execution | `Invoke-CCFParallel` |
| Environment | `Get-CCFPath`, `Initialize-CCFEnvironment`, `Test-CCFHealth`, `Submit-CCFHeartbeat` |

Older names such as `Log-Info`, `Init-CCFLogger`, `Get-CCFPlugins` and `Catch-CCFError` remain as
aliases. See the [API reference](Docs/API-Reference.md) for every command and alias.

## Documentation

- [Getting started](Docs/Getting-Started.md)
- [Configuration guide](Docs/Configuration-Guide.md)
- [Plugin development](Docs/Plugin-Development.md)
- [Security](Docs/Security.md): what is protected, what is not, and a checklist
- [Module structure](Docs/Module-Structure.md)
- [API reference](Docs/API-Reference.md)

## Development

```powershell
.\build.ps1 -InstallDependencies   # first time: Pester 5 and PSScriptAnalyzer
.\build.ps1                        # analysis, tests, and the package in output\ArgosCCF
```

The repository follows the layout of the [Sampler](https://github.com/gaelcolas/Sampler) module
template: the package is built from the runtime files only, and the QA tests check that every
command has complete help, that the code passes PSScriptAnalyzer with
[`PSScriptAnalyzerSettings.psd1`](PSScriptAnalyzerSettings.psd1) (including Windows PowerShell 5.1
compatibility) and that the changelog is up to date. CI runs on Windows PowerShell 5.1 and on
PowerShell 7 on Windows, Linux and macOS, and installs the package with `Install-Module`.
Pushing a `v*` tag publishes the version to the PowerShell Gallery.

See [CONTRIBUTING](.github/CONTRIBUTING.md), [SECURITY](SECURITY.md) and the [CHANGELOG](CHANGELOG.md).

## License

[MIT](LICENSE)
