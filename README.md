# ArgosCCF

[![CI](https://github.com/damdavidprieto/ArgosCCF/actions/workflows/ci.yml/badge.svg)](https://github.com/damdavidprieto/ArgosCCF/actions/workflows/ci.yml)
[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/ArgosCCF.svg)](https://www.powershellgallery.com/packages/ArgosCCF)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Secure logging for PowerShell scripts. Passwords, tokens and keys are removed **before** anything is
written, so a deployment, backup or sync script cannot leak them into a log file, the console or a
SIEM.

```powershell
Write-CCFLogInfo 'Connecting: Server=db01;User Id=sa;Password=P@ss w0rd;Encrypt=True'
# [2026-11-15T10:00:00.000Z] [INFO] [System] Connecting: Server=db01;User Id=sa;Password=[REDACTED];Encrypt=True

Write-CCFLogInfo "GET https://admin:S3cret@files.contoso.com with Authorization: Bearer $jwt"
# ... GET https://admin:[REDACTED]@files.contoso.com with Authorization: Bearer [REDACTED]
```

- **Redaction that knows the formats**: key/value pairs and JSON (`"password": "..."`, values with
  spaces), connection strings, credentials in URLs, `Authorization` headers, bearer tokens, private key
  blocks, JSON web tokens, and GitHub, AWS, Slack, Stripe, Google, npm and `sk-` keys. Random-looking
  strings are caught too, while GUIDs, SIDs, hashes, paths and host names are left alone.
- **Command lines**: `net user`, `schtasks /rp`, `curl -u`, `-Password x`, `--token x` and more, for scripts that log what
  they or others run. A PowerShell `-EncodedCommand` is replaced by a short fingerprint.
- **Your own secrets, wherever they appear**: `Register-CCFSecret` takes the values your script reads
  (or a `PSCredential`) and redacts them in any format, even inside an error message from another
  module. `Register-CCFRedactionPattern` adds formats specific to your organization.
- **Fails closed**: every rule has a time limit. If one runs out or fails, the whole text is replaced
  rather than written unchecked.
- **Works with any logger**: `Protect-CCFSensitiveData` redacts text, hashtables, objects and arrays
  for PSFramework, `Write-Verbose` or your own code, and `Protect-CCFLogFile` cleans transcripts and
  logs that were already written.
- **Logs you can trust**: one entry is always one line, so messages cannot forge entries or hide text
  with terminal escapes. Security and audit records go to their own files, and entries can also go to
  a SIEM.
- **Logs stay yours**: they are kept per user, outside the module folder, so updating or removing the
  module keeps them and an all-users install works without administrator rights.

Windows PowerShell 5.1 and PowerShell 7+ on Windows, Linux and macOS. No dependencies. Every command
has full help: `Get-Help Protect-CCFSensitiveData -Full`.

## Installation

```powershell
Install-Module -Name ArgosCCF -Scope CurrentUser
```

The module loads automatically the first time you call one of its commands.

## Quick start

```powershell
Initialize-CCFLogger -Path (Join-Path $PSScriptRoot 'logs') -FileName 'Deploy.log'

$cred = Get-Credential
Register-CCFSecret -Credential $cred                 # its password is redacted everywhere from now on

Write-CCFLogInfo "Deploying as $($cred.UserName)"
Write-CCFLog -Message 'Calling the API' -Data @{ Uri = $uri; ApiKey = $key }   # ApiKey: [REDACTED]
Write-CCFAuditRecord -Action 'Deploy' -User $env:USERNAME -Resource 'web01'    # CCF_Audit.log
Write-CCFSecurityRecord -Type 'PathTraversal' -Source 'UserInput' -Payload '../../etc/passwd'
try { Invoke-Deployment } catch { Write-CCFErrorRecord -ErrorRecord $_ -Context 'Deploy' }
```

Without `-Path`, logs go to `ArgosCCF\Logs` under `%LOCALAPPDATA%` (`$XDG_DATA_HOME` or
`~/.local/share` on Linux and macOS), or under `$env:CCF_DATA_PATH` when it is set.
`Get-CCFPath -Target Logs` shows where. `Initialize-CCFLogger -JsonOutput` writes one JSON object per
line for a log shipper.

For scripts that log a lot, `Initialize-CCFLogger -Background` writes the files from a background
worker, so each call takes about half the time. Errors, critical entries and security and audit
records still wait until they are on disk, and nothing queued is lost when PowerShell exits.

### With another logger, or on existing files

```powershell
Write-PSFMessage -Message (Protect-CCFSensitiveData "Calling $uri with $body")   # PSFramework
$safe = Protect-CCFSensitiveData @{ User = 'bob'; Password = 'x'; Items = @('token=abc') }

Start-Transcript -Path .\deploy.txt; .\Deploy.ps1; Stop-Transcript
Protect-CCFLogFile -Path .\deploy.txt                # writes deploy.redacted.txt
```

`Get-CCFRedactionPattern` lists every rule in the order it is applied. See
[Security](Docs/Security.md) for exactly what is redacted and what is not.

More in [`Examples/`](Examples/). Each example runs as part of the tests.

## Commands

| Area | Commands |
|---|---|
| Redaction | `Protect-CCFSensitiveData`, `Protect-CCFLogFile`, `Register-CCFSecret`, `Unregister-CCFSecret`, `Register-CCFRedactionPattern`, `Unregister-CCFRedactionPattern`, `Get-CCFRedactionPattern`, `Test-CCFEntropyContent` |
| Logging | `Initialize-CCFLogger`, `Write-CCFLog`, `Write-CCFLogInfo`, `Write-CCFLogSuccess`, `Write-CCFLogWarn`, `Write-CCFLogError`, `Write-CCFLogCritical`, `Write-CCFLogDebug`, `Write-CCFLogHeader`, `Set-CCFLogLevel`, `Register-CCFLogProvider`, `Register-CCFSIEMProvider`, `Remove-CCFOldLog`, `Get-CCFLogWriter`, `Wait-CCFLogWriter`, `Stop-CCFLogWriter` |
| Security and audit records | `Write-CCFSecurityRecord`, `Write-CCFAuditRecord`, `Write-CCFErrorRecord`, `Test-CCFLogChain`, `Get-CCFLogChainHead`, `Register-CCFChainAnchor` |
| Environment | `Get-CCFPath`, `Initialize-CCFEnvironment`, `Test-CCFHealth`, `Submit-CCFHeartbeat` |
| Deprecated (removed in 2.0.0) | Configuration: `Get-CCFConfig`, `Set-CCFUserConfig`, `Merge-CCFConfig`, `Test-CCFConfigSchema`, `Remove-CCFConfigCache`. Plugins: `Get-CCFPlugin`, `Invoke-CCFPlugin`, `Confirm-CCFPluginSignature`. Parallel execution: `Invoke-CCFParallel` |

Older names such as `Log-Info`, `Init-CCFLogger`, `Redact-CCFSensitiveData` and `Catch-CCFError` remain
as aliases. See the [API reference](Docs/API-Reference.md) for every command and alias.

### Deprecated areas

A copy of the module that only needs logging and redaction (for example, one bundled with a tool that runs as
administrator) can leave out `Core/Configuration.ps1`, `Core/Plugins.ps1` and `Core/Execution.ps1`: it loads and exports
the rest.


Up to 1.3, ArgosCCF also offered layered JSON configuration, plugins and parallel execution. They keep
working in 1.x, unchanged except that user settings are now saved in the per-user data folder, but
they will be removed in 2.0.0 so the module can focus on logging. Alternatives: the
[Configuration](https://www.powershellgallery.com/packages/Configuration) or
[PSFramework](https://www.powershellgallery.com/packages/PSFramework) modules for configuration,
ordinary modules for plugins, and `ForEach-Object -Parallel` (PowerShell 7) or
[ThreadJob](https://www.powershellgallery.com/packages/ThreadJob) for parallel work. Plugins still run
only from the `Plugins` folder of the installed module, so copy them again after an update.

## Documentation

- [Security](Docs/Security.md): what is redacted, what is not, and a checklist
- [Getting started](Docs/Getting-Started.md)
- [Module structure](Docs/Module-Structure.md)
- [API reference](Docs/API-Reference.md)
- Deprecated areas: [configuration guide](Docs/Configuration-Guide.md), [plugin development](Docs/Plugin-Development.md)

## Development

```powershell
.\build.ps1 -InstallDependencies   # first time: Pester 5 and PSScriptAnalyzer
.\build.ps1                        # analysis, tests, and the package in output\ArgosCCF
```

The repository follows the layout of the [Sampler](https://github.com/gaelcolas/Sampler) module
template: the package is built from the runtime files only, and the QA tests check that every
command has complete help, that the code passes PSScriptAnalyzer with
[`PSScriptAnalyzerSettings.psd1`](PSScriptAnalyzerSettings.psd1) (including Windows PowerShell 5.1
compatibility) and that the changelog is up to date. The tests write logs to a temporary data folder
(`$env:CCF_DATA_PATH`), never to yours. CI runs on Windows PowerShell 5.1 and on PowerShell 7 on
Windows, Linux and macOS, and installs the package with `Install-Module`. Pushing a `v*` tag
publishes the version to the PowerShell Gallery.

See [CONTRIBUTING](.github/CONTRIBUTING.md), [SECURITY](SECURITY.md) and the [CHANGELOG](CHANGELOG.md).

## License

[MIT](LICENSE)
