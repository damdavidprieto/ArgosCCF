# ArgosCCF API reference

Generated from the comment-based help by `Docs/New-ApiReference.ps1`. In PowerShell, `Get-Help <command> -Full` shows the same information.

| Command | Synopsis |
|---|---|
| [`Add-CCFFolderHash`](#add-ccffolderhash) | Records the hash of a folder (Get-CCFFolderHash) as a chained line of a folder chain log. |
| [`Export-CCFEvidence`](#export-ccfevidence) | Packs logs, their rotated copies, their anchors and the result of checking them into one zip file. |
| [`Get-CCFAnchor`](#get-ccfanchor) | Reads anchors written with Write-CCFAnchor (or in its "<kind> <text>" format by any program). |
| [`Get-CCFChainAnchor`](#get-ccfchainanchor) | Reads the chain anchors that Register-CCFChainAnchor -EventLogSource wrote to the Windows Application log. |
| [`Get-CCFFolderHash`](#get-ccffolderhash) | The SHA-256 of a folder and everything in it: the hash of each file with its relative path, in order. |
| [`Get-CCFLogChainHead`](#get-ccflogchainhead) | The last chain hash of a log, to keep where the log's writer cannot change it. |
| [`Get-CCFLogWriter`](#get-ccflogwriter) | Shows whether log files are written in the background and how many entries are waiting, written or failed. |
| [`Get-CCFPath`](#get-ccfpath) | Returns the full path of one of the ArgosCCF folders. |
| [`Get-CCFRedactionPattern`](#get-ccfredactionpattern) | Lists the redaction rules, in the order they are applied. |
| [`Initialize-CCFEnvironment`](#initialize-ccfenvironment) | Finds the module folders and the per-user folder for logs and settings. |
| [`Initialize-CCFLogger`](#initialize-ccflogger) | Sets the log file for the session and rotates it when it is too large. |
| [`New-CCFChainKey`](#new-ccfchainkey) | Creates the key that signs chained logs, readable only by the account that creates it, or by the accounts given. |
| [`Protect-CCFLogFile`](#protect-ccflogfile) | Writes a redacted copy of a log or transcript file. |
| [`Protect-CCFSensitiveData`](#protect-ccfsensitivedata) | Returns a copy of the data with passwords, tokens, keys and other secrets replaced by [REDACTED]. |
| [`Register-CCFChainAnchor`](#register-ccfchainanchor) | Runs a script block with every new chain head, to save it where the program that writes the log cannot change it. |
| [`Register-CCFLogProvider`](#register-ccflogprovider) | Sends log entries to your own script block instead of the default console output. |
| [`Register-CCFRedactionPattern`](#register-ccfredactionpattern) | Adds a regular expression whose matches are redacted, for secret formats specific to your environment. |
| [`Register-CCFSecret`](#register-ccfsecret) | Registers values that must never appear in a log, wherever they show up. |
| [`Register-CCFSIEMProvider`](#register-ccfsiemprovider) | Forwards every log entry to a script block, for example to send it to a SIEM. |
| [`Remove-CCFOldLog`](#remove-ccfoldlog) | Deletes log files older than -DaysToKeep from the Logs folder, optionally zipping them first. |
| [`Save-CCFChainAnchor`](#save-ccfchainanchor) | Anchors the current head of the chained logs now, whatever -MinimumSeconds says. |
| [`Set-CCFAnchorStore`](#set-ccfanchorstore) | Chooses where anchors go: the Windows Application log (the default) or memory, for tests. |
| [`Set-CCFLogLevel`](#set-ccfloglevel) | Sets the minimum level of the messages that are logged. |
| [`Set-CCFRedactionOption`](#set-ccfredactionoption) | Chooses how the redaction treats PowerShell -EncodedCommand: a fingerprint (the default) or its decoded text. |
| [`Stop-CCFLogWriter`](#stop-ccflogwriter) | Writes the queued log entries and stops the background writer; later entries are written directly. |
| [`Test-CCFEntropyContent`](#test-ccfentropycontent) | Tests whether a string looks like a random secret, such as an API key or a token. |
| [`Test-CCFFolderChain`](#test-ccffolderchain) | Checks a folder chain log (Add-CCFFolderHash) and that the folders still have the hash recorded last. |
| [`Test-CCFHealth`](#test-ccfhealth) | Checks that the Logs folder is writable, and that the chain anchor and the background writer have not failed. |
| [`Test-CCFLogChain`](#test-ccflogchain) | Checks that nobody has changed, inserted or deleted lines of a log written with Initialize-CCFLogger -Chain. |
| [`Unregister-CCFRedactionPattern`](#unregister-ccfredactionpattern) | Removes a pattern added with Register-CCFRedactionPattern. |
| [`Unregister-CCFSecret`](#unregister-ccfsecret) | Removes values registered with Register-CCFSecret. |
| [`Wait-CCFLogWriter`](#wait-ccflogwriter) | Waits until every log entry queued so far has been written to disk. |
| [`Write-CCFAnchor`](#write-ccfanchor) | Writes an anchor of your own to the Windows Application log: a kind and a text, with your source and event ID. |
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

## Add-CCFFolderHash

Records the hash of a folder (Get-CCFFolderHash) as a chained line of a folder chain log.

```powershell
Add-CCFFolderHash [-Folder] <string> [[-LogPath] <string>] [<CommonParameters>]
```

Appends "[FOLDER] <hash> files=<n> <path>" to the log (CCF_Folders.log in the Logs folder by default),
chained like the chained categories: with the identifier, the key and, when Initialize-CCFLogger -WriterInfo
was used, who wrote it. The new head goes to the Register-CCFChainAnchor registration of the Folders
category. Test-CCFFolderChain checks the log and that the folders still have the hash recorded last.
Returns Folder, Hash, Files, Log and Head.

| Parameter | Description |
|---|---|
| `-Folder` | The folder, for example a report folder that will not change any more. |
| `-LogPath` | The folder chain log. Defaults to CCF_Folders.log in the Logs folder. |

**Example 1**

```powershell
Add-CCFFolderHash -Folder .\reports\20261126-101500
```

Records the report folder, so changes to it show later.

## Export-CCFEvidence

Packs logs, their rotated copies, their anchors and the result of checking them into one zip file.

```powershell
Export-CCFEvidence [[-Path] <string[]>] [-Destination] <string> [[-EventLogSource] <string>] [[-EventId] <int>] [[-ChainId] <string>] [[-ChainKeyPath] <string>] [[-Folder] <string[]>] [[-FolderLog] <string>] [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
```

For each log in -Path, copies the file and its rotated copies (with the file locked, so rotation cannot move
them halfway), checks the copies with Test-CCFLogChain -IncludeRotated and writes into the zip: the copies,
evidence.json (when, where and by whom it was made, the ArgosCCF version, the SHA-256 of every file and the
result of each check) and, with -EventLogSource, anchors.json with the anchors that were checked. Returns
Path, Sha256 (of the zip; keep it somewhere else to show the package was not changed later), Valid (every
log checked out) and Logs. The logs are copied as they are: ArgosCCF already redacted them when it wrote
them. Supports -WhatIf and -Confirm.

| Parameter | Description |
|---|---|
| `-Path` | The log files, for example the path of CCF_Audit.log. Their rotated copies are included. |
| `-Destination` | The zip file to create. |
| `-EventLogSource` | Also check, and include, the anchors written by Register-CCFChainAnchor -EventLogSource. |
| `-EventId` | The event ID of those anchors. Defaults to 1100. |
| `-ChainId` | The identifier the logs must carry (see Test-CCFLogChain -ChainId). |
| `-ChainKeyPath` | The key file the logs were signed with (New-CCFChainKey). |
| `-Folder` | Folders to include as they are, for example report folders, with their hash (Get-CCFFolderHash). |
| `-FolderLog` | The folder chain log (Add-CCFFolderHash): each folder in -Folder is compared with the hash recorded last. |
| `-Force` | Replace the zip file if it exists. |

**Example 1**

```powershell
Export-CCFEvidence -Path $auditLog -Destination .\audit-evidence.zip -EventLogSource 'MyApp'
```

Packs the audit log, its anchors and the result of checking them.

## Get-CCFAnchor

Reads anchors written with Write-CCFAnchor (or in its "<kind> <text>" format by any program).

```powershell
Get-CCFAnchor [-Source] <string> [[-EventId] <int[]>] [[-Kind] <string[]>] [[-Since] <datetime>] [[-MaxEvents] <int>] [<CommonParameters>]
```

Returns Time (local), Kind, Text, EventId and Source for each event of the source, oldest first. Anchors
written by other programs in the same format, one word for the kind and the text after a space, are read too.
Remember that any program can write events with any source name: compare anchors with what they anchor.

| Parameter | Description |
|---|---|
| `-Source` | The event source name. |
| `-EventId` | Only these event IDs. |
| `-Kind` | Only these kinds. |
| `-Since` | Only anchors written at or after this time. |
| `-MaxEvents` | The most recent events to read. Defaults to 5000. |

**Example 1**

```powershell
Get-CCFAnchor -Source 'MyApp' -EventId 1001 -Kind 'report' -Since (Get-Date).AddDays(-30)
```

The report anchors of the last 30 days.

## Get-CCFChainAnchor

Reads the chain anchors that Register-CCFChainAnchor -EventLogSource wrote to the Windows Application log.

```powershell
Get-CCFChainAnchor [-EventLogSource] <string> [[-EventId] <int>] [[-Path] <string>] [[-Category] <string>] [[-ChainId] <string>] [[-File] <string>] [[-MaxEvents] <int>] [<CommonParameters>]
```

Returns one object per anchor, oldest first, with File, Folder, Category, Hash, ChainId and Time (UTC). Pass
them to Test-CCFLogChain -ExpectedLastHash: with their time, anchors of copies that rotation or Remove-CCFOldLog
deleted are not required. Filter by -Path (the log file: its name and its folder), -Category, -ChainId and
-File, so the anchors of one log are checked against it, and not those of a log with the same name in another
folder. Events with the same source and ID that are not anchors are ignored.

| Parameter | Description |
|---|---|
| `-EventLogSource` | The source name passed to Register-CCFChainAnchor. |
| `-EventId` | The event ID passed to Register-CCFChainAnchor. Defaults to 1100. |
| `-Path` | Only anchors of this log file. Anchors written before version 2.2.0 carry the file name but not the folder, and are matched by name. |
| `-Category` | Only anchors of this log category, for example Audit. |
| `-ChainId` | Only anchors with this chain identifier (Initialize-CCFLogger -ChainId). |
| `-File` | Only anchors of this log file name, for example CCF_Audit.log, in any folder. |
| `-MaxEvents` | The most recent events to read. Defaults to 5000. |

**Example 1**

```powershell
$anchors = Get-CCFChainAnchor -EventLogSource 'MyApp' -Path $auditLog
Test-CCFLogChain -Path $auditLog -IncludeRotated -ExpectedLastHash $anchors
```

Checks the audit log and that no anchored line is missing.

## Get-CCFFolderHash

The SHA-256 of a folder and everything in it: the hash of each file with its relative path, in order.

```powershell
Get-CCFFolderHash [-Path] <string> [<CommonParameters>]
```

Returns Path, Hash and Files. The hash covers every file under the folder (hidden ones too) by relative path,
with '/' as separator, in ordinal order, as "<path>=<sha256>" lines: renaming, changing, adding or removing
a file changes it. Empty folders do not count.

| Parameter | Description |
|---|---|
| `-Path` | The folder. |

**Example 1**

```powershell
(Get-CCFFolderHash -Path .\reports\20261126-101500).Hash
```

## Get-CCFLogChainHead

The last chain hash of a log, to keep where the log's writer cannot change it.

```powershell
Get-CCFLogChainHead [-Path] <string> [-AsObject] [<CommonParameters>]
```

Returns the hash of the last chained line (of the newest rotated copy when the log was just rotated),
or $null when the log has no chained lines. Keep it somewhere the program that writes the log cannot
change: another machine, an event log, a message. Test-CCFLogChain -ExpectedLastHash then shows whether
lines were deleted from the end afterwards, which the chain alone cannot show.

| Parameter | Description |
|---|---|
| `-Path` | The log file. |
| `-AsObject` | Returns an object with Path, Hash and ChainId instead of the hash, to save whose log the hash belongs to. |

**Example 1**

```powershell
$head = Get-CCFLogChainHead -Path $auditLog
Test-CCFLogChain -Path $auditLog -ExpectedLastHash $head
```

Saves the head now and later checks that no line was removed since.

## Get-CCFLogWriter

Shows whether log files are written in the background and how many entries are waiting, written or failed.

```powershell
Get-CCFLogWriter [<CommonParameters>]
```

Returns an object with Mode ("Background" after Initialize-CCFLogger -Background,
otherwise "Direct"), Running (whether the background writer is working), Queued (file
entries waiting to be written), Written and Failed (entries the background writer
wrote or could not write since it started), LastError (the last write error, if any)
and Capacity (the size of the queue; when it is full, Write-CCFLog waits).

**Example 1**

```powershell
Get-CCFLogWriter
```

Shows the state of the background writer.

**Example 2**

```powershell
if ((Get-CCFLogWriter).Failed) { Write-Warning (Get-CCFLogWriter).LastError }
```

Warns when some entries could not be written to disk.

## Get-CCFPath

Returns the full path of one of the ArgosCCF folders.

```powershell
Get-CCFPath [-Target] <string> [<CommonParameters>]
```

Returns the folder used for Root (the module), Core, Data (the per-user folder for logs, see
Initialize-CCFEnvironment) or Logs: the folder given to Initialize-CCFLogger -Path, or Logs inside the
data folder. Results are cached for the session.

| Parameter | Description |
|---|---|
| `-Target` | The folder to return: Root, Core, Logs or Data. |

**Example 1**

```powershell
Get-CCFPath -Target Logs
```

Returns the folder where log files are written.

**Example 2**

```powershell
Get-ChildItem (Get-CCFPath -Target Logs) -Filter *.log
```

Lists the log files.

## Get-CCFRedactionPattern

Lists the redaction rules, in the order they are applied.

```powershell
Get-CCFRedactionPattern [[-Source] <string>] [<CommonParameters>]
```

Returns one object per rule with its Name, Source (BuiltIn, Custom or Registered),
Description, Pattern and Replacement: registered secret values (count only, never the
values), the built-in rules, the patterns added with Register-CCFRedactionPattern, and
the key/value and entropy rules.

| Parameter | Description |
|---|---|
| `-Source` | Return only BuiltIn, Custom or Registered rules. |

**Example 1**

```powershell
Get-CCFRedactionPattern | Format-Table Name, Source, Description
```

Shows what is redacted and in which order.

## Initialize-CCFEnvironment

Finds the module folders and the per-user folder for logs and settings.

```powershell
Initialize-CCFEnvironment [<CommonParameters>]
```

Runs automatically when the module is imported. ArgosCCF never writes into the folder it
is installed in, so updating or removing the module keeps your logs and settings, and an
all-users install works without administrator rights. Logs and user settings go to the
data folder: $env:CCF_DATA_PATH when it is set, otherwise ArgosCCF under %LOCALAPPDATA%
on Windows, or under $XDG_DATA_HOME or ~/.local/share on Linux and macOS.
If the module folder has no Core folder (for example when only the script files were
copied), the folder in $env:ARGOS_CCF_ROOT is used as the module root instead.
Run it again after changing $env:CCF_DATA_PATH. It also clears the folder chosen with
Initialize-CCFLogger -Path.

**Example 1**

```powershell
$env:CCF_DATA_PATH = 'D:\AppData\Backup'; Initialize-CCFEnvironment; Get-CCFPath -Target Logs
```

Moves the logs and user settings of this session to D:\AppData\Backup.

## Initialize-CCFLogger

Sets the log file for the session and rotates it when it is too large.

```powershell
Initialize-CCFLogger [[-FileName] <string>] [[-Path] <string>] [[-MaxMB] <int>] [[-MaxRolling] <int>] [[-Chain] <string[]>] [[-ChainId] <string>] [[-ChainKeyPath] <string>] [-JsonOutput] [-Background] [-WriterInfo] [-NoConsole] [-Strict] [<CommonParameters>]
```

Until this runs, Write-CCFLog writes System messages to the console only. Afterwards
they also go to the given file in the Logs folder: the folder given with -Path, or
Logs in the per-user data folder (see Get-CCFPath -Target Logs). Logs are never written
into the folder the module is installed in, so updating the module keeps them.
Before every write, a file larger than -MaxMB is renamed to .1 (older copies shift to
.2, .3 and so on, keeping -MaxRolling files) and a new file is started; this applies to
the session file and to the category files, and also when the logger starts.
Messages with another category (Security, Audit, Errors...) always go to their own
CCF_<Category>.log file in the same folder.

| Parameter | Description |
|---|---|
| `-FileName` | Name of the log file, without a folder. Letters, digits, dot, dash and underscore only. Defaults to CCF_Session.log. |
| `-Path` | Folder for the log files of this session, for example your script's own logs folder. It is created if it does not exist; an error is thrown if it cannot be written. Without it, the per-user data folder is used. |
| `-MaxMB` | Size in MB above which the file is rotated. Defaults to 10. |
| `-MaxRolling` | Number of rotated files to keep. Defaults to 5. |
| `-JsonOutput` | Write each entry as one JSON object per line (including Data), instead of plain text. |
| `-Background` | Write log files from a background worker, so Write-CCFLog returns without waiting for the disk. Entries keep their order and are written in batches with the same lock and rotation. The queue holds 10,000 entries; when it is full, Write-CCFLog waits, so no entry is dropped. ERROR and CRITICAL entries, Security and Audit records and entries logged with -NoBuffer wait until they are in the file. The queue is written out when PowerShell exits normally, when the module is removed, by Stop-CCFLogWriter and when Initialize-CCFLogger runs again without -Background; entries still queued when the process is killed are lost. See Get-CCFLogWriter and Wait-CCFLogWriter. |
| `-Chain` | Categories whose log files are tamper-evident, for example 'Audit' and 'Security': every line ends with a hash of itself and of the line before, so Test-CCFLogChain finds a line that was changed, inserted or deleted. Use the category name, or 'System' for the session file. These entries are always written directly, also with -Background. |
| `-ChainId` | Identifier of who writes the chain (letters, digits, '.', '-' and '_'), added to every chained line inside what is hashed. With it, Test-CCFLogChain -ChainId tells lines of another program or another copy apart. |
| `-ChainKeyPath` | Sign the chained categories with the key in this file (New-CCFChainKey), so only who can read the key can write valid lines. Windows only. |
| `-WriterInfo` | Add to every line who wrote it: the account, whether the process was elevated and its process ID, as " #by=<account>;<elevated\|standard>;pid=<id>" (a "Writer" property in JSON). In chained logs it is part of what is hashed, so it cannot be changed afterwards. |
| `-NoConsole` | Do not write the entries to the console (providers still receive them). For scheduled tasks and services, where nobody reads the console and writing to a redirected one is slow. |
| `-Strict` | Entries of the chained categories, and Security and Audit records, that cannot be written throw an error instead of a warning, so a script can stop before doing something it could not record. |

**Example 1**

```powershell
Initialize-CCFLogger -Chain Audit, Security
Audit and Security records can be checked later with Test-CCFLogChain.
```

**Example 2**

```powershell
Initialize-CCFLogger -FileName 'Backup.log' -MaxMB 20
```

Logs to Backup.log, rotated at 20 MB.

**Example 3**

```powershell
Initialize-CCFLogger -JsonOutput
```

Logs JSON lines to CCF_Session.log, for collection by a log shipper.

**Example 4**

```powershell
Initialize-CCFLogger -Path (Join-Path $PSScriptRoot 'logs') -FileName 'Deploy.log'
```

Writes this script's logs, and its Security and Audit records, next to the script.

**Example 5**

```powershell
Initialize-CCFLogger -FileName 'Import.log' -Background
```

Logs to Import.log from a background worker, for scripts that log many entries.

**Example 6**

```powershell
Initialize-CCFLogger -Chain Audit -ChainKeyPath 'C:\ProgramData\MyApp\chain.key' -WriterInfo -NoConsole
```

A scheduled task: signed audit log, with who wrote each line, and nothing on the console.

## New-CCFChainKey

Creates the key that signs chained logs, readable only by the account that creates it, or by the accounts given.

```powershell
New-CCFChainKey [-Path] <string> [[-Reader] <string[]>] [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
```

Writes 32 random bytes, protected with Windows DPAPI, to -Path, and returns the file. Pass the file to
Initialize-CCFLogger -ChainKeyPath: every chained line then carries an HMAC with the key (" #mac=" instead of
" #chain="), so whoever can write the log but cannot read the key cannot add, change or rewrite lines without
Test-CCFLogChain noticing.
By default the key is protected for the current account: create it with the account that writes the log.
Other accounts, including administrators, cannot read it without that account's credentials.
With -Reader, for logs written by several accounts (a daily account and an administrator account), the key is
protected for this computer and the file can be read only by those accounts, SYSTEM and Administrators: its
permissions are what protects it. Any process running as one of those accounts can sign lines, so this
protects against the other accounts of the computer, not against malware running as a reader.
A process running as an account that can read the key can use it, so keep anchors (Register-CCFChainAnchor)
too. Keep the file: without it, logs signed with it cannot be checked. Windows only. Supports -WhatIf and
-Confirm.

| Parameter | Description |
|---|---|
| `-Path` | The key file to create, outside the Logs folder. |
| `-Reader` | Accounts (DOMAIN\user, user, or SIDs) that may read the key, besides the current account, SYSTEM and Administrators. The key then works for each of them, on this computer only. |
| `-Force` | Replace an existing key file. Logs signed with the old key can no longer be checked. |

**Example 1**

```powershell
New-CCFChainKey -Path 'C:\ProgramData\MyApp\chain.key'
Initialize-CCFLogger -Chain Audit -ChainKeyPath 'C:\ProgramData\MyApp\chain.key'
```

Signs the audit log with a key only this account can read.

**Example 2**

```powershell
New-CCFChainKey -Path 'C:\ProgramData\MyApp\chain.key' -Reader "$env:COMPUTERNAME\daily"
```

Run as the administrator account: the key works for it and for the daily account, and for no other.

## Protect-CCFLogFile

Writes a redacted copy of a log or transcript file.

```powershell
Protect-CCFLogFile [-Path] <string> [-Destination <string>] [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
```

Reads the file line by line and writes every line through the same rules as
Protect-CCFSensitiveData. Private key blocks that span several lines are replaced as a
whole. Use it on transcripts (Start-Transcript), logs written by other tools, or old
logs, before sharing or archiving them.
By default the copy is written next to the file as <name>.redacted<extension>. To
overwrite the original, pass it as -Destination as well, with -Force. Returns the source,
the destination and the number of redactions. Supports -WhatIf and -Confirm.

| Parameter | Description |
|---|---|
| `-Path` | The file to redact. Accepts pipeline input, including Get-ChildItem output. |
| `-Destination` | Where to write the redacted copy. Defaults to <name>.redacted<extension> in the same folder. |
| `-Force` | Overwrite the destination if it exists. |

**Example 1**

```powershell
Start-Transcript -Path .\deploy.txt; .\Deploy.ps1; Stop-Transcript; Protect-CCFLogFile -Path .\deploy.txt
```

Writes deploy.redacted.txt without the secrets the deployment printed.

**Example 2**

```powershell
Get-ChildItem C:\Logs -Filter *.log | Protect-CCFLogFile -WhatIf
```

Shows which redacted copies would be written.

## Protect-CCFSensitiveData

Returns a copy of the data with passwords, tokens, keys and other secrets replaced by [REDACTED].

```powershell
Protect-CCFSensitiveData [-InputData] <Object> [-Depth <int>] [<CommonParameters>]
```

Strings are checked, in this order, for values registered with Register-CCFSecret; for
private key blocks, passwords in URLs, Authorization headers, bearer tokens and
connection strings; for GitHub, AWS, Slack, Stripe, Google, npm and sk- keys and JSON
web tokens; for XML elements and command lines (net user, schtasks /rp, -Password,
--token, curl -u and others; a PowerShell -EncodedCommand becomes a short fingerprint);
for patterns added with Register-CCFRedactionPattern; for key/value pairs
whose key names a secret ("password=...", "token: ...", JSON "apiKey": "..."); and for
words that look like random secrets (see Test-CCFEntropyContent), which become
[REDACTED-ENTROPY]. Get-CCFRedactionPattern lists the rules.
An unquoted value ends at the first space, comma or semicolon (connection strings
excepted): in "password: my pass phrase" only "my" is redacted. Quote values that can
contain spaces, or register them with Register-CCFSecret.

Hashtables and objects are copied: values whose key names a secret (password, token,
secret, apikey, authorization, cookie, credential...) or that look like secrets become
[REDACTED] (true/false values are kept), and everything else is checked recursively,
including arrays. SecureString values become [REDACTED]; PSCredential and
NetworkCredential objects keep only the user name. Other objects are replaced by their
text form, redacted, so a password in one of their properties cannot leak. Values
nested more than five levels deep become [DEPTH-LIMIT].

Every rule has a time limit. If a rule runs out of time or fails, the whole string is
replaced instead of being returned unchecked. The input is not modified.
Write-CCFLog applies this to every message and its data. Use it directly to redact
text before passing it to another logger, such as Write-PSFMessage or Write-Verbose.

| Parameter | Description |
|---|---|
| `-InputData` | A string, hashtable, object or array to redact. Accepts pipeline input. |
| `-Depth` | Current nesting level, used internally for recursion. Leave it at 0. |

**Example 1**

```powershell
Protect-CCFSensitiveData -InputData 'login user=admin password=Secr3t!'
```

Returns "login user=admin password=[REDACTED]".

**Example 2**

```powershell
Protect-CCFSensitiveData -InputData 'Server=db01;User Id=sa;Password=P@ss w0rd;Encrypt=True'
```

Returns "Server=db01;User Id=sa;Password=[REDACTED];Encrypt=True".

**Example 3**

```powershell
Protect-CCFSensitiveData -InputData @{ User = 'admin'; ApiKey = 'abc' }
```

Returns a hashtable where ApiKey is "[REDACTED]".

**Example 4**

```powershell
Write-PSFMessage -Message (Protect-CCFSensitiveData "Calling $uri with $headers")
```

Redacts the message before PSFramework writes it.

## Register-CCFChainAnchor

Runs a script block with every new chain head, to save it where the program that writes the log cannot change it.

```powershell
Register-CCFChainAnchor [[-ScriptBlock] <scriptblock>] [-Category <string[]>] [-MinimumSeconds <int>] [<CommonParameters>]

Register-CCFChainAnchor -EventLogSource <string> [-EventId <int>] [-Category <string[]>] [-MinimumSeconds <int>] [<CommonParameters>]
```

After each line of a chained category is written (Initialize-CCFLogger -Chain), the script block receives an
object with Path, Category, Hash, ChainId and Time (UTC). Save it somewhere the log's writer cannot change:
an event log, another machine, a message. Test-CCFLogChain -ExpectedLastHash with those objects then finds
lines deleted from the end, which the chain alone cannot show.
A failure in the script block never stops logging: it is counted, and Test-CCFHealth reports it.
With -EventLogSource, each head is written to the Windows Application log (Get-CCFChainAnchor reads them back).
Any program can write events with a source name, so a forged anchor can raise a false alarm, but cannot hide a
deleted line.
With -Category, the registration applies only to those categories, each with its own -MinimumSeconds; without
it, to every category that has no registration of its own. Without -ScriptBlock or -EventLogSource, removes the
registration of the given categories, or every registration.

| Parameter | Description |
|---|---|
| `-ScriptBlock` | The script block. It receives the anchor object as its only argument. |
| `-EventLogSource` | Write each head to the Windows Application log with this source name. The source does not need to be registered; registering it (New-EventLog, as administrator) lets the Event Viewer show the text. |
| `-EventId` | Event ID for the anchors written with -EventLogSource. Defaults to 1100. |
| `-Category` | Only these categories, for example 'Vigilancia'. Other categories keep their own registration. |
| `-MinimumSeconds` | Run it at most once in this many seconds for each log (the default, 0, runs it for every line). The heads skipped are not lost: the next one covers them, but lines deleted in between cannot be told apart. Use Save-CCFChainAnchor at the end of a task to anchor the last head anyway. |

**Example 1**

```powershell
Register-CCFChainAnchor -ScriptBlock { param($a) Write-EventLog -LogName Application -Source MyApp -EventId 1000 -Message "$($a.Category) $($a.Hash)" }
```

Keeps every head of the chained logs in the Application event log, with your own code.

**Example 2**

```powershell
Register-CCFChainAnchor -EventLogSource 'MyApp'
```

The same, written by ArgosCCF; read them back with Get-CCFChainAnchor -EventLogSource 'MyApp'.

**Example 3**

```powershell
Register-CCFChainAnchor -EventLogSource 'MyApp' -EventId 1101 -Category 'Monitor' -MinimumSeconds 3600
```

Anchors the Monitor log at most once an hour; the other categories keep their own registration.

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

## Register-CCFRedactionPattern

Adds a regular expression whose matches are redacted, for secret formats specific to your environment.

```powershell
Register-CCFRedactionPattern [-Name] <string> [-Pattern] <string> [-Replacement <string>] [<CommonParameters>]
```

Matches are replaced by -Replacement (by default [REDACTED]) in everything ArgosCCF
redacts, after the built-in rules and before the key/value and entropy rules. A pattern
with the same name replaces the earlier one. The pattern must compile, and it gets the
same time limit as the built-in rules: if it runs out of time on some text, that whole
text is replaced, so write patterns that cannot backtrack for long.
Patterns last for the current session.

| Parameter | Description |
|---|---|
| `-Name` | Name of the pattern. Letters, digits, '.', '-' and '_'. Must not be a built-in rule name. |
| `-Pattern` | The regular expression (.NET syntax). Matching is case-sensitive unless the pattern starts with (?i). |
| `-Replacement` | The replacement text. Can refer to named groups, as in '${user}:[REDACTED]'. Defaults to [REDACTED]. |

**Example 1**

```powershell
Register-CCFRedactionPattern -Name 'ContosoKey' -Pattern '\bCTS-[0-9A-F]{24}\b'
```

Redacts Contoso API keys wherever they appear.

## Register-CCFSecret

Registers values that must never appear in a log, wherever they show up.

```powershell
Register-CCFSecret [-Value] <string[]> [<CommonParameters>]

Register-CCFSecret -SecureString <securestring> [<CommonParameters>]

Register-CCFSecret -Credential <pscredential> [<CommonParameters>]
```

From now on, in this session, every occurrence of each value is replaced by [REDACTED]
in everything ArgosCCF redacts: log messages and data, Protect-CCFSensitiveData and
Protect-CCFLogFile. The URL-encoded form of each value is registered too.
Use it for the passwords, keys and tokens your script reads or receives: they are
redacted even in formats no rule knows, such as an error message that quotes them.
Values are kept in memory only, for the current session, and are compared exactly
(case-sensitive). Values shorter than 4 characters are refused, since they would
remove ordinary text. Unregister-CCFSecret removes them.

| Parameter | Description |
|---|---|
| `-Value` | One or more secret values as plain text. Accepts pipeline input. |
| `-SecureString` | A secret stored as a SecureString. |
| `-Credential` | A credential whose password is registered (the user name is not a secret and stays). |

**Example 1**

```powershell
$token = (Get-Secret -Name 'Deploy').GetNetworkCredential().Password; Register-CCFSecret -Value $token
```

Redacts the deployment token from every later log entry.

**Example 2**

```powershell
Register-CCFSecret -Credential $cred
```

Redacts the password of $cred wherever it appears.

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

## Remove-CCFOldLog

Deletes log files older than -DaysToKeep from the Logs folder, optionally zipping them first.

```powershell
Remove-CCFOldLog [[-DaysToKeep] <int>] [-CompressBeforeDelete] [-WhatIf] [-Confirm] [<CommonParameters>]
```

Finds *.log files (and rotated *.log.N files) in the Logs folder whose last write is older
than -DaysToKeep days, optionally compresses them into CCF_Archive_<date>.zip in the same
folder, deletes them and returns their names. Supports -WhatIf and -Confirm.
A chained log (Initialize-CCFLogger -Chain) keeps its current file, and loses only its oldest rotated copies,
oldest first: the deletion is recorded in the current file, so Test-CCFLogChain still checks what is left.
Copies of a signed log are deleted only when the session has its key (Initialize-CCFLogger -ChainKeyPath).

| Parameter | Description |
|---|---|
| `-DaysToKeep` | Age in days of the newest files to keep. Defaults to 30. |
| `-CompressBeforeDelete` | Zip the files before deleting them. If compressing is declined or fails, nothing is deleted. |

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

## Save-CCFChainAnchor

Anchors the current head of the chained logs now, whatever -MinimumSeconds says.

```powershell
Save-CCFChainAnchor [[-Category] <string[]>] [<CommonParameters>]
```

For each chained category of the session (or the ones given), passes the last hash of its log to its
Register-CCFChainAnchor registration, and returns Category, Path and Hash of what it anchored. Use it at the
end of a task that anchors at most once in a while, so lines deleted after the last anchor still show.

| Parameter | Description |
|---|---|
| `-Category` | Only these categories. By default, every chained category (Initialize-CCFLogger -Chain). |

**Example 1**

```powershell
Save-CCFChainAnchor -Category 'Monitor'
```

Anchors the head of CCF_Monitor.log now.

## Set-CCFAnchorStore

Chooses where anchors go: the Windows Application log (the default) or memory, for tests.

```powershell
Set-CCFAnchorStore [[-Store] <string>] [-Clear] [<CommonParameters>]
```

With -Store Memory, Write-CCFAnchor, Register-CCFChainAnchor -EventLogSource and the commands that read
anchors (Get-CCFAnchor, Get-CCFChainAnchor, Test-CCFLogChain -EventLogSource) use a list in memory instead of
the event log, for this session only. Switching to Memory, or -Clear, empties the list.

| Parameter | Description |
|---|---|
| `-Store` | EventLog or Memory. |
| `-Clear` | Empty the anchors kept in memory. |

**Example 1**

```powershell
Set-CCFAnchorStore -Store Memory
```

The tests of a program write and read anchors without touching the event log.

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

## Set-CCFRedactionOption

Chooses how the redaction treats PowerShell -EncodedCommand: a fingerprint (the default) or its decoded text.

```powershell
Set-CCFRedactionOption [-EncodedCommand] <string> [<CommonParameters>]
```

By default the text of -EncodedCommand becomes "[ENCODED <fingerprint> <n> chars]". With -EncodedCommand
Decode it becomes "[DECODED <fingerprint> <n> chars: <text>]": the command decoded (UTF-16, as PowerShell
reads it) and redacted like any other text, so a monitoring tool keeps what was run as evidence without
keeping the secrets in it. A text that does not decode to readable text keeps the fingerprint. The encoded
text itself is never kept: it could carry a password that no rule would see. For this session only.

| Parameter | Description |
|---|---|
| `-EncodedCommand` | Fingerprint or Decode. |

**Example 1**

```powershell
Set-CCFRedactionOption -EncodedCommand Decode
```

Logs what encoded PowerShell commands ran, with their secrets redacted.

## Stop-CCFLogWriter

Writes the queued log entries and stops the background writer; later entries are written directly.

```powershell
Stop-CCFLogWriter [[-TimeoutSeconds] <int>] [<CommonParameters>]
```

Waits up to -TimeoutSeconds for the queued entries to be written, then stops the worker
and frees it. Write-CCFLog then writes each entry before returning, as without
-Background. It also runs by itself when PowerShell exits normally, when the module is
removed or imported again, and when Initialize-CCFLogger runs without -Background.
A warning is written when some entries could not be written.

| Parameter | Description |
|---|---|
| `-TimeoutSeconds` | Longest wait for the queued entries. Entries still queued after it are lost, and a warning says how many. Defaults to 30. |

**Example 1**

```powershell
Stop-CCFLogWriter
```

Writes what is queued and returns to direct writing.

## Test-CCFEntropyContent

Tests whether a string looks like a random secret, such as an API key or a token.

```powershell
Test-CCFEntropyContent [[-String] <string>] [<CommonParameters>]
```

Returns $true for strings of 20 or more characters without spaces, '\', '/' or ':' that
mix upper case letters, lower case letters and digits with no run of more than six lower
case letters in a row (random strings rarely have one; words and identifiers such as
Win32_OperatingSystem do), and for strings of 32 or more characters that mix two of
those kinds with at least one digit in five characters.
GUIDs, Windows SIDs and hexadecimal strings (hashes, certificate thumbprints) are never
flagged: they are common in logs and are not secrets. Neither are command names
(Verb-Noun), Store app package names (Name_8wekyb3d8bbwe) and words joined by '-' or '_'
to hexadecimal parts (code-stable-<commit hash>).
Protect-CCFSensitiveData uses it for values that are not labeled as secrets. It is a
heuristic: it can miss secrets and flag harmless identifiers.

| Parameter | Description |
|---|---|
| `-String` | The text to test. |

**Example 1**

```powershell
Test-CCFEntropyContent -String 'Xk9fQ2mLp7RtZ4vNw8Bc'
```

Returns $true.

**Example 2**

```powershell
Test-CCFEntropyContent -String '3f2504e0-4f89-11d3-9a0c-0305e82c3301'
```

Returns $false: GUIDs are not treated as secrets.

## Test-CCFFolderChain

Checks a folder chain log (Add-CCFFolderHash) and that the folders still have the hash recorded last.

```powershell
Test-CCFFolderChain [[-LogPath] <string>] [[-Root] <string>] [[-KeepDays] <int>] [[-ExpectedLastHash] <Object[]>] [[-EventLogSource] <string>] [[-EventId] <int>] [[-ChainKeyPath] <string>] [[-ChainId] <string>] [-IncludeRotated] [<CommonParameters>]
```

Runs Test-CCFLogChain on the log (with -IncludeRotated, -ExpectedLastHash, -EventLogSource, -ChainKeyPath and
-ChainId as given), then compares each folder with the last hash recorded for it. Returns Valid, Reason,
Entries, Folders, Changed (folders whose content changed), Missing (folders that no longer exist),
DeletedEarly (missing folders recorded less than -KeepDays ago) and Chain (the Test-CCFLogChain result).
Folders deleted on purpose, for example by age, are listed in Missing but do not make the result invalid,
unless they were recorded less than -KeepDays ago.

| Parameter | Description |
|---|---|
| `-LogPath` | The folder chain log. Defaults to CCF_Folders.log in the Logs folder. |
| `-Root` | Look for each folder by its name in this folder, instead of at the path recorded (the folders were moved). |
| `-KeepDays` | Folders are kept at least this many days: a missing folder recorded more recently makes the result invalid. |
| `-IncludeRotated` | Also check the rotated copies of the log. |
| `-ExpectedLastHash` | Heads of the log kept elsewhere (see Test-CCFLogChain). |
| `-EventLogSource` | Check the anchors of the log in the event log (see Test-CCFLogChain). |
| `-EventId` | The event ID of those anchors. Defaults to 1100. |
| `-ChainKeyPath` | The key the log was signed with (see Test-CCFLogChain). |
| `-ChainId` | The identifier the log must carry (see Test-CCFLogChain). |

**Example 1**

```powershell
Test-CCFFolderChain -IncludeRotated -KeepDays 180 -EventLogSource 'MyApp'
```

Checks the report folders, which are deleted after 180 days.

## Test-CCFHealth

Checks that the Logs folder is writable, and that the chain anchor and the background writer have not failed.

```powershell
Test-CCFHealth [-VerifyChain] [<CommonParameters>]
```

Returns an object with Timestamp, Status ("OK" or "DEGRADED") and Checks: one for the
Logs folder, one for the chain anchor when one is registered (no failures) and, with background writing,
one for the writer (running, with no failed writes). With -VerifyChain, one per chained category
(Chain:<Category>) with the result of Test-CCFLogChain -IncludeRotated, using the identifier, the key and the
event log anchors given to Initialize-CCFLogger and Register-CCFChainAnchor.
Status is DEGRADED when any check fails. Use it at the start of a script, or in a
monitoring job, to fail early when the environment is not usable.

| Parameter | Description |
|---|---|
| `-VerifyChain` | Also check the chained logs (Initialize-CCFLogger -Chain). It reads the whole logs, so it takes longer. |

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

**Example 3**

```powershell
(Test-CCFHealth -VerifyChain).Checks | Where-Object Target -like 'Chain:*'
```

Checks that no line of the chained logs was changed or deleted, also against the anchors in the event log.

## Test-CCFLogChain

Checks that nobody has changed, inserted or deleted lines of a log written with Initialize-CCFLogger -Chain.

```powershell
Test-CCFLogChain [-Path] <string> [[-ExpectedLastHash] <Object[]>] [[-ChainId] <string>] [[-EventLogSource] <string>] [[-EventId] <int>] [[-ChainKeyPath] <string>] [[-ClockToleranceSeconds] <int>] [-IncludeRotated] [<CommonParameters>]
```

Recomputes the hash of every chained line from the one before. Returns Path, Entries (chained lines),
Valid, BrokenAt (the first line number that does not match, or $null), Reason, LastHash and ChainId (the
identifier of the last line), ArchivedUntil, MissingHashes, ExternalHashes, KeyedEntries (lines signed with a
chain key) and ClockWarnings (lines whose time is earlier than the line before by more than
-ClockToleranceSeconds: the clock was set back, which can hide when something happened; they do not make the
log invalid, since clocks are also corrected legitimately). Lines written
before the chain was enabled are skipped; an unchained line after a chained one breaks the chain.
With -IncludeRotated the rotated copies (.N down to .1) are checked first and the chain must run across
them from the start; otherwise the first chained line of the file is taken as given, because the line
before it is in a rotated copy. When rotation deleted the oldest copy, the copy left starts from the hash
recorded in its first line, and ArchivedUntil is the time of the last line deleted.
The chain only proves something together with hashes kept where the log's writer cannot change them: whoever
can write the file can also rewrite it and compute new hashes. ExternalHashes is how many were checked;
with 0, Valid only means the file is consistent. Deleting the last lines is not visible either: compare LastHash with a
copy kept elsewhere (-ExpectedLastHash).

| Parameter | Description |
|---|---|
| `-Path` | The log file, for example the path of CCF_Audit.log. |
| `-IncludeRotated` | Also check the rotated copies and the link between them. |
| `-ExpectedLastHash` | Last hashes saved earlier (Get-CCFLogChainHead), one or several: strings, or objects with Hash and Time (when the hash was saved). A hash saved before the last line of a copy that rotation deleted is not required any more. With plain strings, every hash must still be in the log. If the chain no longer contains any of them, lines were deleted or the log was rewritten. With hashes saved over time, a forged later copy cannot hide that an earlier one is gone. |
| `-ChainId` | The identifier this log must carry (Initialize-CCFLogger -ChainId). From the first line that has one, every line must have this one: a line written by another program, or by another copy of the same program, breaks the chain. Keep the identifier where the log's writer cannot change it, and pass only the saved hashes that belong to it: an identifier read from the log itself proves nothing. |
| `-EventLogSource` | Also check the anchors that Register-CCFChainAnchor -EventLogSource wrote for this file (Get-CCFChainAnchor, filtered by the file, its folder and -ChainId when given). Windows only. |
| `-EventId` | The event ID of those anchors. Defaults to 1100. |
| `-ChainKeyPath` | The key file the log was signed with (New-CCFChainKey). Without it, the key given to Initialize-CCFLogger in this session is used. A log with signed lines cannot be checked without the key. With the key, the last line must be signed and no unsigned line may follow a signed one, so the log cannot be rewritten without it. |
| `-ClockToleranceSeconds` | How far back the time of a line may be from the line before without a clock warning. Defaults to 5: lines from several processes can reach the file a little out of order. |

**Example 1**

```powershell
Test-CCFLogChain -Path (Join-Path (Get-CCFPath -Target Logs) 'CCF_Audit.log') -IncludeRotated
```

Checks the whole audit history.

**Example 2**

```powershell
Test-CCFLogChain -Path $auditLog -IncludeRotated -EventLogSource 'MyApp' -ChainKeyPath 'C:\ProgramData\MyApp\chain.key'
```

Checks the signed audit log and that none of the heads kept in the event log is missing.

## Unregister-CCFRedactionPattern

Removes a pattern added with Register-CCFRedactionPattern.

```powershell
Unregister-CCFRedactionPattern [-Name] <string> [<CommonParameters>]
```

Removes the named pattern. Built-in rules cannot be removed. Writes an error if no
pattern has that name.

| Parameter | Description |
|---|---|
| `-Name` | Name of the pattern to remove. Accepts pipeline input by property name, so the output of Get-CCFRedactionPattern -Source Custom can be piped. |

**Example 1**

```powershell
Unregister-CCFRedactionPattern -Name 'ContosoKey'
```

Stops redacting Contoso keys by pattern.

## Unregister-CCFSecret

Removes values registered with Register-CCFSecret.

```powershell
Unregister-CCFSecret [-Value] <string[]> [<CommonParameters>]

Unregister-CCFSecret -All [<CommonParameters>]
```

Removes the given values (and their URL-encoded forms), or all of them with -All, so
they are no longer redacted by value. The other rules keep working.

| Parameter | Description |
|---|---|
| `-Value` | The values to remove. |
| `-All` | Remove every registered value. |

**Example 1**

```powershell
Unregister-CCFSecret -All
```

Forgets every registered secret.

## Wait-CCFLogWriter

Waits until every log entry queued so far has been written to disk.

```powershell
Wait-CCFLogWriter [[-TimeoutSeconds] <int>] [<CommonParameters>]
```

With Initialize-CCFLogger -Background, Write-CCFLog returns before the entry is in the
file. Wait-CCFLogWriter blocks until every entry logged before the call is written,
for example before reading or copying the log file, or before a step that may stop
the process. The background writer keeps running. Without a background writer it
returns at once. Write-CCFLog already waits by itself for ERROR and CRITICAL entries,
Security and Audit records and entries logged with -NoBuffer.

| Parameter | Description |
|---|---|
| `-TimeoutSeconds` | Longest wait. A warning is written when the entries are not written in time. Defaults to 30. |

**Example 1**

```powershell
Write-CCFLogInfo 'Report generated'; Wait-CCFLogWriter; Copy-Item (Get-CCFPath -Target Logs) \\server\logs -Recurse
```

Makes sure the entry is in the file before the logs are copied.

## Write-CCFAnchor

Writes an anchor of your own to the Windows Application log: a kind and a text, with your source and event ID.

```powershell
Write-CCFAnchor [-Source] <string> [-EventId] <int> [-Kind] <string> [[-Text] <string>] [<CommonParameters>]
```

Writes "<Kind> <Text>" as an information event with the source and event ID you choose, and returns $true when
the event log accepted it. Use it to keep, out of reach of the program that wrote them, hashes and
identifiers that are not log heads: the hash of a report, of a settings file, a heartbeat. Get-CCFAnchor
reads them back. The source does not need to be registered. The text is not redacted: write hashes and
identifiers, never secrets. Line breaks and control characters are removed. Windows only (or the memory
store, see Set-CCFAnchorStore).

| Parameter | Description |
|---|---|
| `-Source` | The event source name, for example 'MyApp'. |
| `-EventId` | The event ID; one per kind lets readers filter by ID. |
| `-Kind` | What the anchor is: letters, digits, '.', '-' and '_'. |
| `-Text` | The text: a hash, a name, a time. |

**Example 1**

```powershell
Write-CCFAnchor -Source 'MyApp' -EventId 1001 -Kind 'report' -Text "20261126-101500 $hash"
```

Keeps the hash of a report in the Application log.

## Write-CCFAuditRecord

Records who did what, on which resource, in CCF_Audit.log.

```powershell
Write-CCFAuditRecord [-Action] <string> [-User] <string> [[-Resource] <string>] [[-Outcome] <string>] [[-Metadata] <hashtable>] [-Strict] [<CommonParameters>]
```

Logs "[AUDIT] <User> <Action> <Resource>" at INFO level in the Audit category, with the
outcome and metadata as data. Use it for actions that must be traceable, such as
deletions or configuration changes.

| Parameter | Description |
|---|---|
| `-Action` | What was done, for example FileDeletion. |
| `-User` | Who did it. |
| `-Resource` | Optional target of the action, for example a file path. |
| `-Outcome` | Success (the default) or Failure. |
| `-Metadata` | Optional extra data. |
| `-Strict` | Throw an error if the record cannot be written, instead of a warning. |

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
Write-CCFLog [-Message] <string> [-Level <string>] [-Color <string>] [-Data <hashtable>] [-Category <string>] [-NoBuffer] [-Strict] [<CommonParameters>]
```

Ignores the message if its level is below the one set with Set-CCFLogLevel. Otherwise
it redacts secrets from the message and data (Protect-CCFSensitiveData) and then:
writes the entry to the console, or passes it to the provider registered with
Register-CCFLogProvider; passes it to the SIEM provider, if any; and appends it to the
log file. Entries in the System category go to the file set with Initialize-CCFLogger;
other categories go to CCF_<Category>.log in the Logs folder.
Line breaks in the message are written as "\n" and control characters are removed, so
a message cannot add fake entries to the log or restyle the console.
Files are written as UTF-8 without BOM. Each write locks the file with a named mutex,
so runspaces and processes (of the same user session) that log to the same file at the
same time neither lose nor interleave entries.
After Initialize-CCFLogger -Background the file line is queued and written by a
background worker, so the call returns sooner; console output and providers are not
affected. ERROR and CRITICAL entries, Security and Audit records and entries logged
with -NoBuffer wait until they are in the file.

| Parameter | Description |
|---|---|
| `-Message` | The message to log. |
| `-Level` | INFO (the default), SUCCESS, WARN, ERROR, CRITICAL or DEBUG. |
| `-Color` | Console color for INFO messages when no provider is registered. Defaults to White. |
| `-Data` | Optional structured data. It is redacted, passed to the providers and written to the file in JSON mode (Initialize-CCFLogger -JsonOutput). |
| `-Category` | Log category, which also names the log file. Letters, digits, dot, dash and underscore. Defaults to System. |
| `-NoBuffer` | With background writing (Initialize-CCFLogger -Background), wait until this entry is in the file before returning. Without background writing every entry is written before Write-CCFLog returns, so it has no effect. |
| `-Strict` | Throw an error when the entry cannot be written to its file, instead of a warning. Initialize-CCFLogger -Strict does this for the chained categories and for Security and Audit records. |

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
failures that need immediate attention. Message and Data can be passed by position.

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
Set-CCFLogLevel -Level DEBUG.
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
does not write to the error stream or stop the script. Message and Data can be passed by position.

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
script in the log.

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

Shortcut for Write-CCFLog -Level INFO.
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

Shortcut for Write-CCFLog -Level SUCCESS, shown in green on the console. Message and Data can be passed by position.

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

Shortcut for Write-CCFLog -Level WARN, shown in yellow on the console. Message and Data can be passed by position.

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
Write-CCFSecurityRecord [-Type] <string> [-Source] <string> [[-Payload] <string>] [[-Severity] <string>] [[-Metadata] <hashtable>] [-Strict] [<CommonParameters>]
```

Logs "[SECURITY] <Type> from <Source>" in the Security category, with the type, source,
payload and metadata as data (redacted like any other log data). Use it when the
script detects or blocks something suspicious.

| Parameter | Description |
|---|---|
| `-Type` | Kind of event, for example PathTraversal or BruteForce. |
| `-Source` | Where it came from, for example an IP address or an input name. |
| `-Payload` | Optional offending value. It is logged as data, after redaction. |
| `-Severity` | WARN (the default), ERROR or CRITICAL. |
| `-Metadata` | Optional extra data. |
| `-Strict` | Throw an error if the record cannot be written, instead of a warning. |

**Example 1**

```powershell
Write-CCFSecurityRecord -Type 'PathTraversal' -Source 'UserInput' -Payload '../../etc/passwd'
```

Records a blocked path traversal attempt.
