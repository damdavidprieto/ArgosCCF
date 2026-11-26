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
Initialize-CCFLogger -Path (Join-Path $PSScriptRoot 'logs') -FileName 'MyApp.log' -MaxMB 50 -MaxRolling 5

Write-CCFLogInfo 'Application started'
Write-CCFLogWarn 'Low disk space' @{ Drive = 'C:'; FreePercent = 9 }
Write-CCFLogError 'Could not connect to the database'
Write-CCFLogSuccess 'Done'
```

Messages go to the console and to `MyApp.log` in the folder given with `-Path`. Without `-Path` they
go to the per-user data folder (`Get-CCFPath -Target Logs`), never into the module folder, so updating
the module keeps them. `Set-CCFLogLevel -Level DEBUG` also logs `Write-CCFLogDebug` messages, and
`Initialize-CCFLogger -JsonOutput` writes one JSON object per line.

Scripts that log many entries can add `-Background`: the files are then written by a background
worker and each `Write-CCFLog` call takes about half the time. Errors, critical entries and security
and audit records still wait until they are on disk, and the queue is written out when PowerShell
exits. Call `Wait-CCFLogWriter` before reading or copying the log files.

Security and audit events go to their own files in the same folder:

```powershell
Write-CCFAuditRecord -Action 'FileDeletion' -User $env:USERNAME -Resource 'C:\Data\db.bak'   # CCF_Audit.log
Write-CCFSecurityRecord -Type 'BruteForce' -Source '10.0.0.5' -Severity ERROR                # CCF_Security.log
try { Remove-Item $path -ErrorAction Stop } catch { Write-CCFErrorRecord -ErrorRecord $_ }  # CCF_Errors.log
```

## 2. Redaction

Every message and its data are redacted before they are written: passwords and tokens in key/value
pairs and JSON, connection strings, URLs, `Authorization` headers, private keys, known token formats
and random-looking strings. Tell ArgosCCF about the secrets your script handles, so they are redacted
in any format:

```powershell
$cred = Get-Credential
Register-CCFSecret -Credential $cred
Register-CCFSecret -Value $env:DEPLOY_TOKEN
Register-CCFRedactionPattern -Name 'ContosoKey' -Pattern '\bCTS-[0-9A-F]{24}\b'

Write-CCFLogError "Login failed: $($error[0])"     # the password and the token never reach the log
Get-CCFRedactionPattern | Format-Table Name, Source, Description
```

The same redaction works without ArgosCCF's logger:

```powershell
Write-Verbose (Protect-CCFSensitiveData $response)
Write-PSFMessage -Message (Protect-CCFSensitiveData "Calling $uri")      # PSFramework
Protect-CCFLogFile -Path .\transcript.txt                                 # writes transcript.redacted.txt
```

See [Security](Security.md) for the full list of rules and their limits.

## Tamper-evident logs

```powershell
$key = 'C:\ProgramData\MyApp\chain.key'
if (-not (Test-Path $key)) { $null = New-CCFChainKey -Path $key }   # once, as the account that writes the log
Initialize-CCFLogger -Chain Audit -ChainId 'deploy-01' -ChainKeyPath $key -WriterInfo
Register-CCFChainAnchor -EventLogSource 'MyApp'      # every head also goes to the Application log
Write-CCFAuditRecord -Action 'Deploy' -User $env:USERNAME -Resource 'web01' -Strict

$auditLog = Join-Path (Get-CCFPath -Target Logs) 'CCF_Audit.log'
Test-CCFLogChain -Path $auditLog -IncludeRotated -ChainId 'deploy-01' -ChainKeyPath $key -EventLogSource 'MyApp'
(Test-CCFHealth -VerifyChain).Status                 # the same for every chained log of the session
Export-CCFEvidence -Path $auditLog -Destination .\audit.zip -EventLogSource 'MyApp' -ChainKeyPath $key
```

For a scheduled task or a service, add `-NoConsole`: nobody reads that console, and writing to it costs time.

```powershell
# A log that is checked once a day: anchored at most once an hour, and at the end of each run.
Register-CCFChainAnchor -EventLogSource 'MyApp' -EventId 1106 -Category 'Monitor' -MinimumSeconds 3600
Save-CCFChainAnchor -Category 'Monitor'

# Report folders: recorded when they are finished, checked later, deleted after 180 days.
Add-CCFFolderHash -Folder $reportFolder
Test-CCFFolderChain -IncludeRotated -KeepDays 180

# Anchors of your own, in the format "<kind> <text>".
Write-CCFAnchor -Source 'MyApp' -EventId 1003 -Kind 'settings' -Text $settingsHash
Get-CCFAnchor -Source 'MyApp' -EventId 1003 -Since (Get-Date).AddDays(-30)
```

## Examples

The `Examples/` folder has one runnable script per area: `01-Logging.ps1` and `05-Redaction.ps1`.

## Next

- [Security](Security.md): what ArgosCCF redacts and how to use it safely.
- [API reference](API-Reference.md): every command, or `Get-Help <command> -Full`.
