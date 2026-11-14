# ArgosCCF API reference

Generated from the comment-based help by `Docs/New-ApiReference.ps1`. In PowerShell, `Get-Help <command> -Full` shows the same information.

| Command | Synopsis |
|---|---|
| [`Confirm-CCFPluginSignature`](#confirm-ccfpluginsignature) | Checks whether a plugin file has a valid Authenticode signature. |
| [`Get-CCFConfig`](#get-ccfconfig) | Loads a configuration by name, merging the factory, preset and user layers. |
| [`Get-CCFPath`](#get-ccfpath) | Returns the full path of one of the ArgosCCF folders. |
| [`Get-CCFPlugin`](#get-ccfplugin) | Lists the plugins in the Plugins folder (or another folder) with their metadata. |
| [`Initialize-CCFEnvironment`](#initialize-ccfenvironment) | Finds the module folders and chooses a writable folder for the logs. |
| [`Initialize-CCFLogger`](#initialize-ccflogger) | Sets the log file for the session and rotates it when it is too large. |
| [`Invoke-CCFParallel`](#invoke-ccfparallel) | Runs a script block for each input object in parallel and returns one result per object. |
| [`Invoke-CCFPlugin`](#invoke-ccfplugin) | Runs a plugin from the Plugins folder, with its lifecycle hooks and optional sandboxing. |
| [`Merge-CCFConfig`](#merge-ccfconfig) | Merges one configuration object into another, recursively. |
| [`Protect-CCFSensitiveData`](#protect-ccfsensitivedata) | Returns a copy of the data with passwords, tokens and other secrets replaced by [REDACTED]. |
| [`Register-CCFLogProvider`](#register-ccflogprovider) | Sends log entries to your own script block instead of the default console output. |
| [`Register-CCFSIEMProvider`](#register-ccfsiemprovider) | Forwards every log entry to a script block, for example to send it to a SIEM. |
| [`Remove-CCFConfigCache`](#remove-ccfconfigcache) | Clears the in-memory configuration cache. |
| [`Remove-CCFOldLog`](#remove-ccfoldlog) | Deletes log files older than -DaysToKeep from the Logs folder, optionally zipping them first. |
| [`Set-CCFLogLevel`](#set-ccfloglevel) | Sets the minimum level of the messages that are logged. |
| [`Set-CCFUserConfig`](#set-ccfuserconfig) | Saves user settings for a configuration and clears its cached copies. |
| [`Submit-CCFHeartbeat`](#submit-ccfheartbeat) | Records that the registered log provider is alive. |
| [`Test-CCFConfigSchema`](#test-ccfconfigschema) | Validates a configuration object against a simple schema and fills in defaults. |
| [`Test-CCFEntropyContent`](#test-ccfentropycontent) | Tests whether a string looks like a secret, such as an API key or a token. |
| [`Test-CCFHealth`](#test-ccfhealth) | Checks that the ArgosCCF components are loaded and that the Logs folder is writable. |
| [`Write-CCFAuditRecord`](#write-ccfauditrecord) | Records who did what, on which resource, in CCF_Audit.log. |
| [`Write-CCFErrorRecord`](#write-ccferrorrecord) | Logs an error record from a catch block to CCF_Errors.log. |
| [`Write-CCFLog`](#write-ccflog) | Writes a log entry to the console, the registered providers and the log file. |
| [`Write-CCFLogCritical`](#write-ccflogcritical) | Logs a message at CRITICAL level. |
| [`Write-CCFLogDebug`](#write-ccflogdebug) | Logs a message at DEBUG level. |
| [`Write-CCFLogError`](#write-ccflogerror) | Logs a message at ERROR level. |
| [`Write-CCFLogHeader`](#write-ccflogheader) | Logs a section header at INFO level, shown in cyan. |
| [`Write-CCFLogInfo`](#write-ccfloginfo) | Logs a message at INFO level. |
| [`Write-CCFLogSuccess`](#write-ccflogsuccess) | Logs a message at SUCCESS level. |
| [`Write-CCFLogWarn`](#write-ccflogwarn) | Logs a message at WARN level. |
| [`Write-CCFSecurityRecord`](#write-ccfsecurityrecord) | Records a security event, such as an attack attempt or a blocked action, in CCF_Security.log. |

## Aliases

Names from earlier versions, kept so existing scripts keep working.

| Alias | Command |
|---|---|
| `Catch-CCFError` | `Write-CCFErrorRecord` |
| `Clear-CCFConfigCache` | `Remove-CCFConfigCache` |
| `Get-CCFPlugins` | `Get-CCFPlugin` |
| `Init-CCFLogger` | `Initialize-CCFLogger` |
| `Log-Attack` | `Write-CCFSecurityRecord` |
| `Log-Audit` | `Write-CCFAuditRecord` |
| `Log-Critical` | `Write-CCFLogCritical` |
| `Log-Debug` | `Write-CCFLogDebug` |
| `Log-Error` | `Write-CCFLogError` |
| `Log-Header` | `Write-CCFLogHeader` |
| `Log-Info` | `Write-CCFLogInfo` |
| `Log-Success` | `Write-CCFLogSuccess` |
| `Log-Warn` | `Write-CCFLogWarn` |
| `Redact-CCFSensitiveData` | `Protect-CCFSensitiveData` |
| `Remove-OldCCFLogs` | `Remove-CCFOldLog` |
| `Test-CCFHighEntropy` | `Test-CCFEntropyContent` |
| `Test-CCFPluginSignature` | `Confirm-CCFPluginSignature` |

## Confirm-CCFPluginSignature

Checks whether a plugin file has a valid Authenticode signature.

```powershell
Confirm-CCFPluginSignature [-Path] <string> [<CommonParameters>]
```

Returns a hashtable with Valid ($true only for a valid, trusted signature), Status and,
when valid, Signer. Self-signed certificates that are not trusted on the machine, and
any platform without Authenticode (Linux, macOS), return Valid = $false: the check
fails closed. Invoke-CCFPlugin runs this check on the exact bytes it is about to run
when RequireSignedPlugins is enabled. The alias Test-CCFPluginSignature is kept for
older scripts.

| Parameter | Description |
|---|---|
| `-Path` | Path to the plugin file. |

**Example 1**

```powershell
(Confirm-CCFPluginSignature -Path .\Plugins\Backup\Backup.ps1).Valid
```

Returns $true when the plugin is signed with a trusted certificate.

## Get-CCFConfig

Loads a configuration by name, merging the factory, preset and user layers.

```powershell
Get-CCFConfig [-ConfigName] <string> [[-ActivePresets] <string[]>] [-ForceRefresh] [<CommonParameters>]
```

Reads Configs/Factory/<ConfigName>.json, merges the section named <ConfigName> of each
preset in Configs/Presets/<preset>.json, then merges Configs/User/<ConfigName>.json, and
returns the result. The result is cached per name and preset list; use -ForceRefresh
or Remove-CCFConfigCache after changing the files. Names must be plain file names:
anything that looks like a path is refused and logged as a security block.
The returned object is the cached one, so changes to it are visible to later calls.

| Parameter | Description |
|---|---|
| `-ConfigName` | Name of the configuration, without .json. Letters, digits, '.', '-' and '_'. |
| `-ActivePresets` | Presets to apply, in order, between the factory and the user layers. |
| `-ForceRefresh` | Read the files again instead of returning the cached result. |

**Example 1**

```powershell
(Get-CCFConfig -ConfigName 'ccf_core').Logging
```

Returns the logging section of the core configuration.

**Example 2**

```powershell
Get-CCFConfig -ConfigName 'demo_app' -ActivePresets 'Production' -ForceRefresh
```

Reloads demo_app with the Production preset applied.

## Get-CCFPath

Returns the full path of one of the ArgosCCF folders.

```powershell
Get-CCFPath [-Target] <string> [<CommonParameters>]
```

Returns the folder used for Root, Core, Configs, Logs, Tests or Plugins. Results are
cached for the session. The Logs folder can be changed with Logging.DefaultPath in the
ccf_core configuration; the override is used only when, after resolving "..", it is
inside the module root or inside $env:CCF_DATA_PATH. Otherwise it is ignored and a
warning is logged, so a configuration file cannot send logs to an arbitrary folder.

| Parameter | Description |
|---|---|
| `-Target` | The folder to return: Root, Core, Configs, Logs, Tests or Plugins. |

**Example 1**

```powershell
Get-CCFPath -Target Logs
```

Returns the folder where log files are written.

**Example 2**

```powershell
Get-ChildItem (Get-CCFPath -Target Plugins) -Recurse -Filter *.ps1
```

Lists the plugin scripts.

## Get-CCFPlugin

Lists the plugins in the Plugins folder (or another folder) with their metadata.

```powershell
Get-CCFPlugin [[-Path] <string>] [<CommonParameters>]
```

Finds every .ps1 file in the folder and its subfolders and returns one object per
plugin with Name, Description, Version, Author, Path, Signed and Manifest.
Metadata comes from a ccf_plugin.json file in the plugin's folder (Name, Version,
Author, Description) or, failing that, from comment keywords in the script
(.NAME, .DESCRIPTION, .VERSION, .AUTHOR, or CCF_PLUGIN_NAME: and similar).
Listing a plugin does not run it. The alias Get-CCFPlugins is kept for older scripts.

| Parameter | Description |
|---|---|
| `-Path` | Folder to search. Defaults to the module's Plugins folder. |

**Example 1**

```powershell
Get-CCFPlugin | Format-Table Name, Version, Signed
```

Lists the installed plugins and whether they are signed.

**Example 2**

```powershell
Get-CCFPlugin | Where-Object Name -EQ 'HelloWorld' | ForEach-Object { Invoke-CCFPlugin -Plugin $_ }
```

Finds a plugin by name and runs it.

## Initialize-CCFEnvironment

Finds the module folders and chooses a writable folder for the logs.

```powershell
Initialize-CCFEnvironment [<CommonParameters>]
```

Runs automatically when the module is imported. It creates the Configs and Plugins
folders if they are missing and chooses the Logs folder: next to the module when it
is writable, otherwise (for example when installed for all users under Program Files)
ArgosCCF\Logs under %LOCALAPPDATA%, $XDG_DATA_HOME or ~/.local/share.
If the module folder has no Core folder (for example when only the script files were
copied), the folder in $env:ARGOS_CCF_ROOT is used as the root instead.

**Example 1**

```powershell
Initialize-CCFEnvironment; Get-CCFPath -Target Logs
```

Chooses the folders again and shows where the logs are written.

## Initialize-CCFLogger

Sets the log file for the session and rotates it when it is too large.

```powershell
Initialize-CCFLogger [[-FileName] <string>] [[-MaxMB] <int>] [[-MaxRolling] <int>] [-JsonOutput] [<CommonParameters>]
```

Until this runs, Write-CCFLog writes System messages to the console only. Afterwards
they also go to the given file in the Logs folder (see Get-CCFPath -Target Logs).
If the file is larger than -MaxMB, it is renamed to .1 (older copies shift to .2, .3
and so on, keeping -MaxRolling files) and a new file is started.
Messages with another category (Security, Audit, Errors...) always go to their own
CCF_<Category>.log file in the same folder.

| Parameter | Description |
|---|---|
| `-FileName` | Name of the log file, without a folder. Letters, digits, dot, dash and underscore only. Defaults to CCF_Session.log. |
| `-MaxMB` | Size in MB above which the file is rotated. Defaults to 10. |
| `-MaxRolling` | Number of rotated files to keep. Defaults to 5. |
| `-JsonOutput` | Write each entry as one JSON object per line (including Data), instead of plain text. |

**Example 1**

```powershell
Initialize-CCFLogger -FileName 'Backup.log' -MaxMB 20
```

Logs to Backup.log, rotated at 20 MB.

**Example 2**

```powershell
Initialize-CCFLogger -JsonOutput
```

Logs JSON lines to CCF_Session.log, for collection by a log shipper.

## Invoke-CCFParallel

Runs a script block for each input object in parallel and returns one result per object.

```powershell
Invoke-CCFParallel [-ScriptBlock] <scriptblock> [-InputObjects] <array> [[-MaxThreads] <int>] [[-Arguments] <hashtable>] [[-RetryCount] <int>] [[-RetryDelayMs] <int>] [[-OnProgress] <scriptblock>] [<CommonParameters>]
```

Runs -ScriptBlock once per input object in a pool of runspaces, up to -MaxThreads at a
time, and returns one object per input, in input order, with Target, Output, Status
("Success" or "Failed"), Error, Retries, Duration (seconds) and Index.
The script block receives the input object as its first argument and -Arguments as
the second. It runs in a separate runspace: it cannot see your variables or functions,
and is rebuilt from its text, so pass everything it needs as arguments.
A failure in one object does not stop the others; with -RetryCount it is retried after
-RetryDelayMs. -OnProgress is called in your session after each object finishes.

| Parameter | Description |
|---|---|
| `-ScriptBlock` | Code to run for each object. Receives ($inputObject, $arguments). |
| `-InputObjects` | The objects to process. |
| `-MaxThreads` | Maximum number of objects processed at the same time. Defaults to the number of processors; values below 2 are raised to 2. |
| `-Arguments` | Hashtable passed to every run as the second argument. |
| `-RetryCount` | Number of extra attempts for an object whose script block throws. Defaults to 0. |
| `-RetryDelayMs` | Milliseconds to wait between attempts. Defaults to 500. |
| `-OnProgress` | Optional script block called as ($processedCount, $totalCount) after each object. |

**Example 1**

```powershell
Invoke-CCFParallel -InputObjects 'server1', 'server2' -ScriptBlock { param($name) Test-Connection $name -Count 1 -Quiet }
```

Pings both servers at the same time and returns one result per server.

**Example 2**

```powershell
$results = Invoke-CCFParallel -InputObjects (1..20) -MaxThreads 4 -RetryCount 2 -ScriptBlock {
    param($n, $config) Invoke-RestMethod "$($config.Url)/items/$n"
} -Arguments @{ Url = 'https://api.example.com' }
$results | Where-Object Status -EQ 'Failed'
```

Fetches 20 items, four at a time with two retries each, and lists the failures.

## Invoke-CCFPlugin

Runs a plugin from the Plugins folder, with its lifecycle hooks and optional sandboxing.

```powershell
Invoke-CCFPlugin [-Plugin] <psobject> [[-Arguments] <hashtable>] [-SkipHooks] [-HardenedMode] [<CommonParameters>]
```

Checks, in order:
1. The plugin must be a .ps1 file inside the module's Plugins folder (after resolving
"..", so paths cannot escape it). Anything else is refused and logged as CRITICAL.
2. When RequireSignedPlugins is enabled in the ccf_core configuration, the plugin must
have a valid Authenticode signature. The signature is checked on the same bytes
that are then run, so the file cannot be swapped between check and execution.
Then it runs the plugin's Before-Execute function (if defined), the plugin script with
-Arguments, and its After-Execute function with the result, and returns the result.
With -HardenedMode the plugin and its hooks run in a new restricted runspace in
ConstrainedLanguage mode: no cmdlets, no providers, and no calls to non-core .NET
methods. This reduces what a plugin can do but is not a security boundary without
WDAC or AppLocker; combine it with RequireSignedPlugins for code you did not write.
Errors are logged with Write-CCFErrorRecord and the function returns $null.

| Parameter | Description |
|---|---|
| `-Plugin` | Plugin object from Get-CCFPlugin, or any object with Name and Path. |
| `-Arguments` | Hashtable passed to the plugin (and to Before-Execute) as -Arguments. |
| `-SkipHooks` | Do not run Before-Execute and After-Execute. |
| `-HardenedMode` | Run the plugin and its hooks in a restricted ConstrainedLanguage runspace. |

**Example 1**

```powershell
$plugin = Get-CCFPlugin | Where-Object Name -EQ 'SystemInfo'
Invoke-CCFPlugin -Plugin $plugin -Arguments @{ Detail = 'Full' }
```

Runs the SystemInfo plugin with an argument.

**Example 2**

```powershell
Invoke-CCFPlugin -Plugin $plugin -HardenedMode
```

Runs the plugin in the restricted runspace.

## Merge-CCFConfig

Merges one configuration object into another, recursively.

```powershell
Merge-CCFConfig [-Base] <psobject> [-Override] <psobject> [<CommonParameters>]
```

Copies every property of -Override into -Base and returns -Base. Nested objects are
merged property by property, arrays are concatenated, and any other value in -Override
replaces the one in -Base. -Base is modified in place; pass a copy if you need to keep
the original. Get-CCFConfig uses it to apply presets and user settings.

| Parameter | Description |
|---|---|
| `-Base` | The object to merge into. It is modified. |
| `-Override` | The object whose values take precedence. |

**Example 1**

```powershell
$base = '{"Logging":{"Level":"INFO","Path":"Logs"}}' | ConvertFrom-Json
$over = '{"Logging":{"Level":"DEBUG"}}' | ConvertFrom-Json
(Merge-CCFConfig -Base $base -Override $over).Logging
```

Returns Level = DEBUG and Path = Logs.

## Protect-CCFSensitiveData

Returns a copy of the data with passwords, tokens and other secrets replaced by [REDACTED].

```powershell
Protect-CCFSensitiveData [-InputData] <Object> [[-Depth] <int>] [<CommonParameters>]
```

Strings: "password=...", "token: ..." and similar pairs are replaced by "password=[REDACTED]",
and words that look like secrets (see Test-CCFEntropyContent) by "[REDACTED-ENTROPY]".
Hashtables and objects: values whose key names a secret (password, token, secret,
apikey, authorization...) or that look like secrets are replaced by "[REDACTED]", and
nested hashtables and objects are processed too. Values nested more than five levels
deep are replaced by "[DEPTH-LIMIT]" instead of being logged unchecked.
The input is not modified. Write-CCFLog applies this to every message and its data.

| Parameter | Description |
|---|---|
| `-InputData` | A string, hashtable or object to redact. Other types are returned unchanged. |
| `-Depth` | Current nesting level, used internally for recursion. Leave it at 0. |

**Example 1**

```powershell
Protect-CCFSensitiveData -InputData 'login user=admin password=Secr3t!'
```

Returns "login user=admin password=[REDACTED]".

**Example 2**

```powershell
Protect-CCFSensitiveData -InputData @{ User = 'admin'; ApiKey = 'abc' }
```

Returns a hashtable where ApiKey is "[REDACTED]".

## Register-CCFLogProvider

Sends log entries to your own script block instead of the default console output.

```powershell
Register-CCFLogProvider [-ProviderScript] <scriptblock> [<CommonParameters>]
```

Once registered, Write-CCFLog calls the script block for every entry instead of writing
it with Write-Host. The script block receives one hashtable argument with two keys:
Entry (the log entry: Timestamp, Level, Category, Message, Data, Context) and Color.
Use it to route logs to a UI module such as HermesConsoleUI. If the provider throws,
the entry is written to the console instead. Log files are not affected.

| Parameter | Description |
|---|---|
| `-ProviderScript` | Script block that receives @{ Entry = ...; Color = ... } for each log entry. |

**Example 1**

```powershell
Register-CCFLogProvider -ProviderScript {
    param($e)
    Write-ConsoleStatus -Message $e.Entry.Message -Type Info
}
```

Shows every log message with HermesConsoleUI.

## Register-CCFSIEMProvider

Forwards every log entry to a script block, for example to send it to a SIEM.

```powershell
Register-CCFSIEMProvider [-ProviderScript] <scriptblock> [<CommonParameters>]
```

After console output, Write-CCFLog calls the script block with one hashtable argument
whose Entry key holds the log entry, with secrets already redacted. Errors in the
provider are ignored so that logging never stops the script.

| Parameter | Description |
|---|---|
| `-ProviderScript` | Script block that receives @{ Entry = ... } for each log entry. |

**Example 1**

```powershell
Register-CCFSIEMProvider -ProviderScript {
    param($e)
    $e.Entry | ConvertTo-Json -Compress | Add-Content -Path C:\siem\outbox.jsonl
}
```

Appends every entry, as JSON, to a file a SIEM agent collects.

## Remove-CCFConfigCache

Clears the in-memory configuration cache.

```powershell
Remove-CCFConfigCache [<CommonParameters>]
```

Removes every cached result of Get-CCFConfig, so the next call reads the JSON files
again. Use it after editing configuration files outside Set-CCFUserConfig. The files
are not touched. The alias Clear-CCFConfigCache is kept for older scripts.

**Example 1**

```powershell
Remove-CCFConfigCache
```

Clears the cache.

## Remove-CCFOldLog

Deletes log files older than -DaysToKeep from the Logs folder, optionally zipping them first.

```powershell
Remove-CCFOldLog [[-DaysToKeep] <int>] [-CompressBeforeDelete] [-WhatIf] [-Confirm] [<CommonParameters>]
```

Finds *.log files (and rotated *.log.N files) in the Logs folder whose last write is older
than -DaysToKeep days, optionally compresses them into CCF_Archive_<date>.zip in the same
folder, deletes them and returns their names. Supports -WhatIf and -Confirm.
The alias Remove-OldCCFLogs is kept for older scripts.

| Parameter | Description |
|---|---|
| `-DaysToKeep` | Age in days of the newest files to keep. Defaults to 30. |
| `-CompressBeforeDelete` | Zip the files before deleting them. |

**Example 1**

```powershell
Remove-CCFOldLog -DaysToKeep 30 -CompressBeforeDelete
```

Archives and deletes logs older than 30 days.

**Example 2**

```powershell
Remove-CCFOldLog -DaysToKeep 7 -WhatIf
```

Shows which logs would be deleted.

## Set-CCFLogLevel

Sets the minimum level of the messages that are logged.

```powershell
Set-CCFLogLevel [-Level] <string> [<CommonParameters>]
```

Messages below this level are ignored by Write-CCFLog and the level shortcuts. The order
is DEBUG, INFO, WARN (SUCCESS has the same weight as WARN), ERROR, CRITICAL.
The default level is INFO. The setting lasts for the current session.

| Parameter | Description |
|---|---|
| `-Level` | The minimum level to log: DEBUG, INFO, WARN, ERROR or CRITICAL. |

**Example 1**

```powershell
Set-CCFLogLevel -Level DEBUG
```

Logs everything, including Write-CCFLogDebug messages.

**Example 2**

```powershell
Set-CCFLogLevel -Level ERROR
```

Logs only errors and critical messages.

## Set-CCFUserConfig

Saves user settings for a configuration and clears its cached copies.

```powershell
Set-CCFUserConfig [-ConfigName] <string> [-ConfigObject] <psobject> [-WhatIf] [-Confirm] [<CommonParameters>]
```

Writes -ConfigObject as JSON (UTF-8) to Configs/User/<ConfigName>.json, the top layer
that Get-CCFConfig merges over the factory and preset layers. Cached results for that
name are removed, so the next Get-CCFConfig reads the new values.
Names must be plain file names; anything that looks like a path is refused.
Supports -WhatIf and -Confirm.

| Parameter | Description |
|---|---|
| `-ConfigName` | Name of the configuration, without .json. Letters, digits, '.', '-' and '_'. |
| `-ConfigObject` | The settings to save. Usually only the values that differ from the factory file. |

**Example 1**

```powershell
Set-CCFUserConfig -ConfigName 'ccf_core' -ConfigObject ([pscustomobject]@{ Security = @{ RequireSignedPlugins = $true } })
```

Requires signed plugins for this installation.

## Submit-CCFHeartbeat

Records that the registered log provider is alive.

```powershell
Submit-CCFHeartbeat [<CommonParameters>]
```

Stores the current time as the provider's last heartbeat. A UI or SIEM provider can call
it periodically so that a host script can tell whether the provider is still active.

**Example 1**

```powershell
Submit-CCFHeartbeat
```

Records a heartbeat now.

## Test-CCFConfigSchema

Validates a configuration object against a simple schema and fills in defaults.

```powershell
Test-CCFConfigSchema [-Config] <psobject> [-Schema] <hashtable> [<CommonParameters>]
```

The schema is a hashtable with one entry per property. Each entry is a hashtable that
can contain Mandatory ($true/$false), Type (a .NET type such as [int]), AllowedValues
(an array) and Default. Missing properties with a Default are added to -Config.
Returns $true when the configuration is valid; otherwise logs each problem at ERROR
level and returns $false.

| Parameter | Description |
|---|---|
| `-Config` | The configuration object to check. Defaults are added to it. |
| `-Schema` | Hashtable describing the expected properties. |

**Example 1**

```powershell
$schema = @{
    Port = @{ Mandatory = $true; Type = [int] }
    Mode = @{ AllowedValues = 'Audit', 'Enforce'; Default = 'Audit' }
}
Test-CCFConfigSchema -Config ([pscustomobject]@{ Port = 8080 }) -Schema $schema
```

Returns $true and adds Mode = Audit to the object.

## Test-CCFEntropyContent

Tests whether a string looks like a secret, such as an API key or a token.

```powershell
Test-CCFEntropyContent [[-String] <string>] [<CommonParameters>]
```

Returns $true for strings of 20 or more characters without spaces or path characters
that mix at least three kinds of characters (upper case, lower case, digits, - _ + =),
or two kinds when longer than 32 characters. Protect-CCFSensitiveData uses it to
redact values that are not labeled as secrets. It is a heuristic: it can miss secrets
and flag harmless identifiers.

| Parameter | Description |
|---|---|
| `-String` | The text to test. |

**Example 1**

```powershell
Test-CCFEntropyContent -String 'AKIA-872H-J92K-LL92-MM102-PP01'
```

Returns $true.

**Example 2**

```powershell
Test-CCFEntropyContent -String 'C:\Windows\System32'
```

Returns $false: paths are not treated as secrets.

## Test-CCFHealth

Checks that the ArgosCCF components are loaded and that the Logs folder is writable.

```powershell
Test-CCFHealth [<CommonParameters>]
```

Returns an object with Timestamp, Status ("OK" or "DEGRADED") and Checks, one entry per
component (Logging, Configuration, Execution, Plugins) and one for the Logs folder.
Status is DEGRADED when any check fails. Use it at the start of a script, or in a
monitoring job, to fail early when the environment is not usable.

**Example 1**

```powershell
(Test-CCFHealth).Status
```

Returns "OK" when everything is available.

**Example 2**

```powershell
Test-CCFHealth | Select-Object -ExpandProperty Checks | Where-Object { -not $_.Pass }
```

Lists the checks that failed.

## Write-CCFAuditRecord

Records who did what, on which resource, in CCF_Audit.log.

```powershell
Write-CCFAuditRecord [-Action] <string> [-User] <string> [[-Resource] <string>] [[-Outcome] <string>] [[-Metadata] <hashtable>] [<CommonParameters>]
```

Logs "[AUDIT] <User> <Action> <Resource>" at INFO level in the Audit category, with the
outcome and metadata as data. Use it for actions that must be traceable, such as
deletions or configuration changes. The alias Log-Audit is kept for older scripts.

| Parameter | Description |
|---|---|
| `-Action` | What was done, for example FileDeletion. |
| `-User` | Who did it. |
| `-Resource` | Optional target of the action, for example a file path. |
| `-Outcome` | Success (the default) or Failure. |
| `-Metadata` | Optional extra data. |

**Example 1**

```powershell
Write-CCFAuditRecord -Action 'FileDeletion' -User $env:USERNAME -Resource 'C:\Data\db.bak'
```

Records that the current user deleted the file.

## Write-CCFErrorRecord

Logs an error record from a catch block to CCF_Errors.log.

```powershell
Write-CCFErrorRecord [-ErrorRecord] <ErrorRecord> [[-Context] <string>] [<CommonParameters>]
```

Writes the exception message at ERROR level in the Errors category, with the exception
type and the script stack trace as data. Use it in catch blocks to keep a trace of
failures without stopping the script.

| Parameter | Description |
|---|---|
| `-ErrorRecord` | The error record, usually $_ inside a catch block. |
| `-Context` | Short text identifying where the error happened. Defaults to "General". |

**Example 1**

```powershell
try { Get-Item C:\missing -ErrorAction Stop } catch { Write-CCFErrorRecord -ErrorRecord $_ -Context 'Startup' }
```

Logs "[Startup] Cannot find path ..." with the stack trace.

## Write-CCFLog

Writes a log entry to the console, the registered providers and the log file.

```powershell
Write-CCFLog [-Message] <string> [-Level <string>] [-Color <string>] [-Data <hashtable>] [-Category <string>] [-NoBuffer] [<CommonParameters>]
```

Ignores the message if its level is below the one set with Set-CCFLogLevel. Otherwise
it redacts secrets from the message and data (Protect-CCFSensitiveData) and then:
writes the entry to the console, or passes it to the provider registered with
Register-CCFLogProvider; passes it to the SIEM provider, if any; and appends it to the
log file. Entries in the System category go to the file set with Initialize-CCFLogger;
other categories go to CCF_<Category>.log in the Logs folder.
Line breaks in the message are written as "\n" and control characters are removed, so
a message cannot add fake entries to the log or restyle the console.

| Parameter | Description |
|---|---|
| `-Message` | The message to log. |
| `-Level` | INFO (the default), SUCCESS, WARN, ERROR, CRITICAL or DEBUG. |
| `-Color` | Console color for INFO messages when no provider is registered. Defaults to White. |
| `-Data` | Optional structured data. It is redacted, passed to the providers and written to the file in JSON mode (Initialize-CCFLogger -JsonOutput). |
| `-Category` | Log category, which also names the log file. Letters, digits, dot, dash and underscore. Defaults to System. |
| `-NoBuffer` | Kept for compatibility; entries are always written immediately. |

**Example 1**

```powershell
Write-CCFLog -Message 'Backup started' -Level INFO
```

Logs an informational message.

**Example 2**

```powershell
Write-CCFLog -Message 'Login failed' -Level WARN -Category Security -Data @{ User = 'admin' }
```

Logs a warning to CCF_Security.log with the user name as data.

## Write-CCFLogCritical

Logs a message at CRITICAL level.

```powershell
Write-CCFLogCritical [-Message] <string> [[-Data] <hashtable>] [<CommonParameters>]
```

Shortcut for Write-CCFLog -Level CRITICAL, shown in magenta on the console, for
failures that need immediate attention. The alias Log-Critical is kept for older
scripts. Message and Data can be passed by position.

| Parameter | Description |
|---|---|
| `-Message` | The message to log. |
| `-Data` | Optional structured data, redacted before it is logged. |

**Example 1**

```powershell
Write-CCFLogCritical 'Security policy could not be applied'
```

Logs a critical message.

## Write-CCFLogDebug

Logs a message at DEBUG level.

```powershell
Write-CCFLogDebug [-Message] <string> [[-Data] <hashtable>] [<CommonParameters>]
```

Shortcut for Write-CCFLog -Level DEBUG. Debug messages are only logged after
Set-CCFLogLevel -Level DEBUG. The alias Log-Debug is kept for older scripts.
Message and Data can be passed by position.

| Parameter | Description |
|---|---|
| `-Message` | The message to log. |
| `-Data` | Optional structured data, redacted before it is logged. |

**Example 1**

```powershell
Set-CCFLogLevel -Level DEBUG; Write-CCFLogDebug 'Cache hit for ccf_core'
```

Logs a debug message.

## Write-CCFLogError

Logs a message at ERROR level.

```powershell
Write-CCFLogError [-Message] <string> [[-Data] <hashtable>] [<CommonParameters>]
```

Shortcut for Write-CCFLog -Level ERROR, shown in red on the console. It only logs: it
does not write to the error stream or stop the script. The alias Log-Error is kept for
older scripts. Message and Data can be passed by position.

| Parameter | Description |
|---|---|
| `-Message` | The message to log. |
| `-Data` | Optional structured data, redacted before it is logged. |

**Example 1**

```powershell
Write-CCFLogError 'Could not reach the database'
```

Logs an error message.

## Write-CCFLogHeader

Logs a section header at INFO level, shown in cyan.

```powershell
Write-CCFLogHeader [-Message] <string> [<CommonParameters>]
```

Shortcut for Write-CCFLog -Level INFO -Color Cyan, to mark the start of a phase of a
script in the log. The alias Log-Header is kept for older scripts.

| Parameter | Description |
|---|---|
| `-Message` | The header text. |

**Example 1**

```powershell
Write-CCFLogHeader 'Phase 2: applying settings'
```

Logs the header.

## Write-CCFLogInfo

Logs a message at INFO level.

```powershell
Write-CCFLogInfo [-Message] <string> [[-Data] <hashtable>] [<CommonParameters>]
```

Shortcut for Write-CCFLog -Level INFO. The alias Log-Info is kept for older scripts.
Message and Data can be passed by position.

| Parameter | Description |
|---|---|
| `-Message` | The message to log. |
| `-Data` | Optional structured data, redacted before it is logged. |

**Example 1**

```powershell
Write-CCFLogInfo 'Configuration loaded'
```

Logs an informational message.

## Write-CCFLogSuccess

Logs a message at SUCCESS level.

```powershell
Write-CCFLogSuccess [-Message] <string> [[-Data] <hashtable>] [<CommonParameters>]
```

Shortcut for Write-CCFLog -Level SUCCESS, shown in green on the console. The alias
Log-Success is kept for older scripts. Message and Data can be passed by position.

| Parameter | Description |
|---|---|
| `-Message` | The message to log. |
| `-Data` | Optional structured data, redacted before it is logged. |

**Example 1**

```powershell
Write-CCFLogSuccess 'Backup completed'
```

Logs a success message.

## Write-CCFLogWarn

Logs a message at WARN level.

```powershell
Write-CCFLogWarn [-Message] <string> [[-Data] <hashtable>] [<CommonParameters>]
```

Shortcut for Write-CCFLog -Level WARN, shown in yellow on the console. The alias
Log-Warn is kept for older scripts. Message and Data can be passed by position.

| Parameter | Description |
|---|---|
| `-Message` | The message to log. |
| `-Data` | Optional structured data, redacted before it is logged. |

**Example 1**

```powershell
Write-CCFLogWarn 'Disk space below 10%' @{ Drive = 'C:' }
```

Logs a warning with the drive as data.

## Write-CCFSecurityRecord

Records a security event, such as an attack attempt or a blocked action, in CCF_Security.log.

```powershell
Write-CCFSecurityRecord [-Type] <string> [-Source] <string> [[-Payload] <string>] [[-Severity] <string>] [[-Metadata] <hashtable>] [<CommonParameters>]
```

Logs "[SECURITY] <Type> from <Source>" in the Security category, with the type, source,
payload and metadata as data (redacted like any other log data). Use it when the
script detects or blocks something suspicious. The alias Log-Attack is kept for older
scripts.

| Parameter | Description |
|---|---|
| `-Type` | Kind of event, for example PathTraversal or BruteForce. |
| `-Source` | Where it came from, for example an IP address or an input name. |
| `-Payload` | Optional offending value. It is logged as data, after redaction. |
| `-Severity` | WARN (the default), ERROR or CRITICAL. |
| `-Metadata` | Optional extra data. |

**Example 1**

```powershell
Write-CCFSecurityRecord -Type 'PathTraversal' -Source 'UserInput' -Payload '../../etc/passwd'
```

Records a blocked path traversal attempt.
