# Getting started

## Install

```powershell
Install-Module -Name ArgosCCF -Scope CurrentUser
```

Windows PowerShell 5.1 or PowerShell 7+. The module loads automatically the first time you call one
of its commands. To work from source instead:

```powershell
git clone https://github.com/damdavidprieto/ArgosCCF.git
Import-Module .\ArgosCCF\ArgosCCF.psd1
```

## 1. Logging

```powershell
Initialize-CCFLogger -FileName 'MyApp.log' -MaxMB 50 -MaxRolling 5

Write-CCFLogInfo 'Application started'
Write-CCFLogWarn 'Low disk space' @{ Drive = 'C:'; FreePercent = 9 }
Write-CCFLogError 'Could not connect to the database'
Write-CCFLogSuccess 'Done'
```

Messages go to the console and to `MyApp.log` in `Get-CCFPath -Target Logs`. Secrets in messages and
data are redacted. `Set-CCFLogLevel -Level DEBUG` also logs `Write-CCFLogDebug` messages, and
`Initialize-CCFLogger -JsonOutput` writes one JSON object per line.

## 2. Configuration

Configurations are JSON files under `Configs`: factory defaults in `Factory/<name>.json`, optional
presets in `Presets/<preset>.json` and user overrides in `User/<name>.json`, merged in that order.

```powershell
$config = Get-CCFConfig -ConfigName 'app_settings' -ActivePresets 'production'
$config.Database.Host

Set-CCFUserConfig -ConfigName 'app_settings' -ConfigObject ([pscustomobject]@{ Database = @{ Host = 'localhost' } })
```

See the [configuration guide](Configuration-Guide.md).

## 3. Plugins

```powershell
Get-CCFPlugin | Format-Table Name, Version, Signed
$plugin = Get-CCFPlugin | Where-Object Name -EQ 'HelloWorld'
Invoke-CCFPlugin -Plugin $plugin -Arguments @{ Name = 'Ana' }
```

See [plugin development](Plugin-Development.md).

## 4. Parallel execution

```powershell
$results = Invoke-CCFParallel -InputObjects 'Server01', 'Server02', 'Server03' -MaxThreads 3 -ScriptBlock {
    param($server)
    Test-Connection -ComputerName $server -Count 1 -Quiet
}

foreach ($result in $results) {
    "$($result.Target): $($result.Status) $($result.Output)"
}
```

The script block runs in its own runspace: pass what it needs with `-Arguments`.

## Examples

The `Examples/` folder has one runnable script per area: `01-Logging.ps1`, `02-Configuration.ps1`,
`03-Plugins.ps1` and `04-Parallel.ps1`.

## Next

- [Security](Security.md): what ArgosCCF protects and how to use it safely.
- [API reference](API-Reference.md): every command, or `Get-Help <command> -Full`.
