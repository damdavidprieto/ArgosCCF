# ArgosCCF logging engine.
#
# Writes log entries to the console (or a registered provider), to a SIEM provider and to log
# files, after redacting secrets (Redaction.ps1). Also provides security and audit records, log
# rotation and clean-up, and a health check.

$script:LogProvider = $null
$script:SIEMProvider = $null
$script:CurrentLogFile = $null
$script:MaxLogSizeMB = 10
$script:MaxLogRolling = 5
$script:CCFMutexNames = [System.Collections.Concurrent.ConcurrentDictionary[string, string]]::new()
$script:CCFLogEncoding = [System.Text.UTF8Encoding]::new($false)
$script:LogLevels = @{ 'DEBUG' = 0; 'INFO' = 1; 'WARN' = 2; 'SUCCESS' = 2; 'ERROR' = 3; 'CRITICAL' = 4 }
$script:CurrentLogLevel = 1
$script:JsonOutput = $false
$script:LastProviderHeartbeat = $null

# --- Private helpers ---

function ConvertTo-CCFLogText {
    <#
    .SYNOPSIS
        Makes text safe to write as one log line: control characters cannot forge entries.
    .DESCRIPTION
        Line breaks become the literal text "\n" (and "\r"), so a message cannot start a new,
        fake log entry. ANSI escape sequences and other control characters are removed, so a
        message cannot restyle the console or hide text.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$Text)

    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $clean = $Text -replace '\x1B\][^\x07\x1B]*(\x07|\x1B\\)?', ''
    $clean = $clean -replace '(\x1B\[|\x9B)[0-?]*[ -/]*[@-~]', ''
    $clean = $clean -replace '\x1B[@-_]?', ''
    $clean = $clean -replace "`r", '\r' -replace "`n", '\n' -replace "`t", ' '
    return ($clean -replace '[\x00-\x1F\x7F-\x9F]', '')
}

function Test-CCFLogName {
    <#
    .SYNOPSIS
        True when a name can be used as part of a log file name inside the Logs folder.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowEmptyString()][string]$Name)

    return ($Name -match '^[A-Za-z0-9][A-Za-z0-9._-]*$' -and $Name -notmatch '\.\.')
}

function Get-CCFFileMutexName {
    <#
    .SYNOPSIS
        Name of the mutex that serializes writes to one log file, the same in every runspace and process.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Path)

    $name = $null
    if ($script:CCFMutexNames.TryGetValue($Path, [ref]$name)) { return $name }

    $key = [System.IO.Path]::GetFullPath($Path)
    if (-not ($IsLinux -or $IsMacOS)) { $key = $key.ToUpperInvariant() }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = [System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($key)), 0, 16).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }

    $name = "ArgosCCF-$hash"
    $null = $script:CCFMutexNames.TryAdd($Path, $name)
    return $name
}

function Invoke-CCFLogRotation {
    <#
    .SYNOPSIS
        Renames a log file to .1 (shifting older copies, keeping MaxRolling of them) when it is larger than MaxMB.
    .DESCRIPTION
        Uses .NET calls only, so the background writer can run it without loading cmdlets.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$MaxMB = 10,
        [int]$MaxRolling = 5
    )

    $info = [System.IO.FileInfo]::new($Path)
    if (-not $info.Exists -or $info.Length -le ([long]$MaxMB * 1MB)) { return }

    for ($i = $MaxRolling - 1; $i -ge 0; $i--) {
        $old = if ($i -eq 0) { $Path } else { "$Path.$i" }
        $new = "$Path.$($i + 1)"
        if (-not [System.IO.File]::Exists($old)) { continue }
        if ([System.IO.File]::Exists($new)) { [System.IO.File]::Delete($new) }
        [System.IO.File]::Move($old, $new)
    }
}

function Add-CCFLogText {
    <#
    .SYNOPSIS
        Appends text (one or more complete lines) to a log file, rotating it first if needed, with the file locked for every runspace and process.
    .DESCRIPTION
        A named mutex derived from the file path makes writers wait for each other, so concurrent
        writes from runspaces or other processes are neither lost nor interleaved. If the lock is
        not obtained within 5 seconds the text is written anyway: logging never blocks a script.
        A missing folder is created. A write that fails because the file is briefly in use
        (antivirus, backup) is retried. Uses .NET calls only, so the background writer can run
        it without loading cmdlets.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text,
        [int]$MaxMB = 10,
        [int]$MaxRolling = 5
    )

    $mutex = [System.Threading.Mutex]::new($false, (Get-CCFFileMutexName -Path $Path))
    $locked = $false
    try {
        try { $locked = $mutex.WaitOne(5000) }
        catch [System.Threading.AbandonedMutexException] { $locked = $true }
        if (-not $locked) { Write-Verbose "No lock on $Path after 5 seconds; writing anyway." }

        Invoke-CCFLogRotation -Path $Path -MaxMB $MaxMB -MaxRolling $MaxRolling
        for ($attempt = 1; $attempt -le 5; $attempt++) {
            try {
                [System.IO.File]::AppendAllText($Path, $Text, $script:CCFLogEncoding)
                return
            }
            catch [System.IO.DirectoryNotFoundException] {
                if ($attempt -eq 5) { throw }
                $null = [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($Path))
            }
            catch [System.IO.IOException] {
                if ($attempt -eq 5) { throw }
                [System.Threading.Thread]::Sleep(20 * $attempt)
            }
        }
    }
    finally {
        if ($locked) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

# --- Background writer ---
#
# With Initialize-CCFLogger -Background, Write-CCFLog puts each file line in a bounded queue and
# returns; one worker runspace per module instance takes the lines in order and appends them in
# batches (one lock and one write per file per batch). The worker runs copies of the three file
# helpers above, so it writes with the same lock, rotation and retries as direct writes.
# A wait marker (a ManualResetEventSlim) put in the queue is set once every line before it has
# been written; Wait-CCFLogWriter and the entries that must reach the disk use it.

$script:CCFWriter = $null
$script:CCFWriterCapacity = 10000

$script:CCFWriterScript = {
    param($Queue, $Status)
    $batch = [System.Collections.Generic.List[object]]::new()
    while ($true) {
        $item = $null
        try {
            if (-not $Queue.TryTake([ref]$item, 250)) {
                if ($Queue.IsCompleted) { break }
                continue
            }
        }
        catch [System.ObjectDisposedException] { break }
        catch [System.InvalidOperationException] { break }

        $batch.Clear()
        $batch.Add($item)
        while ($batch.Count -lt 1000 -and $Queue.TryTake([ref]$item)) { $batch.Add($item) }

        $i = 0
        while ($i -lt $batch.Count) {
            $first = $batch[$i]
            if ($first -is [System.Threading.ManualResetEventSlim]) {
                try { $first.Set() } catch { $null = $_ }
                $i++
                continue
            }
            # Consecutive lines for the same file are written together.
            $text = [System.Text.StringBuilder]::new()
            $count = 0
            while ($i -lt $batch.Count -and $batch[$i] -isnot [System.Threading.ManualResetEventSlim] -and $batch[$i][0] -ceq $first[0]) {
                $null = $text.Append($batch[$i][1])
                $count++
                $i++
            }
            try {
                Add-CCFLogText -Path $first[0] -Text $text.ToString() -MaxMB $first[2] -MaxRolling $first[3]
                $Status.Written += $count
            }
            catch {
                $Status.Failed += $count
                $Status.LastError = "$($first[0]): $($_.Exception.Message)"
            }
        }
    }
}

function Initialize-CCFLogWriter {
    <#
    .SYNOPSIS
        Starts the background writer of this module instance, if it is not running.
    #>
    [CmdletBinding()]
    param()

    if ($null -ne $script:CCFWriter) { return }

    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
    foreach ($name in 'Get-CCFFileMutexName', 'Invoke-CCFLogRotation', 'Add-CCFLogText') {
        $definition = (Get-Item -LiteralPath "function:$name").ScriptBlock.ToString()
        $iss.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($name, $definition))
    }
    $iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('CCFMutexNames', $script:CCFMutexNames, ''))
    $iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('CCFLogEncoding', $script:CCFLogEncoding, ''))

    $queue = [System.Collections.Concurrent.BlockingCollection[object]]::new($script:CCFWriterCapacity)
    $status = [hashtable]::Synchronized(@{ Written = [long]0; Failed = [long]0; LastError = $null })
    $runspace = [runspacefactory]::CreateRunspace($iss)
    $runspace.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $runspace
    $null = $ps.AddScript($script:CCFWriterScript.ToString()).AddArgument($queue).AddArgument($status)
    $handle = $ps.BeginInvoke()

    # Write what is still queued when PowerShell exits normally.
    $exitJob = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action { Close-CCFLogWriter -TimeoutSeconds 10 -Exiting }

    $script:CCFWriter = @{
        Queue = $queue; Status = $status; Runspace = $runspace; PowerShell = $ps; Handle = $handle; ExitJob = $exitJob
    }
}

function Add-CCFQueuedLogText {
    <#
    .SYNOPSIS
        Puts text for a log file in the background writer's queue; false when it cannot (the caller then writes it directly).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text
    )

    $writer = $script:CCFWriter
    if ($null -eq $writer) { return $false }
    if ($writer.PowerShell.InvocationStateInfo.State -ne 'Running') {
        Write-Warning 'ArgosCCF: the background log writer stopped; log entries are written directly from now on.'
        Stop-CCFLogWriter -TimeoutSeconds 0 -WarningAction SilentlyContinue
        return $false
    }
    try {
        # A full queue makes the caller wait (no entry is dropped); after 5 seconds it writes directly.
        return $writer.Queue.TryAdd(@($Path, $Text, $script:MaxLogSizeMB, $script:MaxLogRolling), 5000)
    }
    catch {
        return $false
    }
}

function Get-CCFLogWriter {
    <#
    .SYNOPSIS
        Shows whether log files are written in the background and how many entries are waiting, written or failed.

    .DESCRIPTION
        Returns an object with Mode ("Background" after Initialize-CCFLogger -Background,
        otherwise "Direct"), Running (whether the background writer is working), Queued (file
        entries waiting to be written), Written and Failed (entries the background writer
        wrote or could not write since it started), LastError (the last write error, if any)
        and Capacity (the size of the queue; when it is full, Write-CCFLog waits).

    .EXAMPLE
        Get-CCFLogWriter

        Shows the state of the background writer.

    .EXAMPLE
        if ((Get-CCFLogWriter).Failed) { Write-Warning (Get-CCFLogWriter).LastError }

        Warns when some entries could not be written to disk.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $writer = $script:CCFWriter
    if ($null -eq $writer) {
        return [pscustomobject]@{ Mode = 'Direct'; Running = $false; Queued = 0; Written = 0; Failed = 0; LastError = $null; Capacity = $script:CCFWriterCapacity }
    }
    return [pscustomobject]@{
        Mode      = 'Background'
        Running   = ($writer.PowerShell.InvocationStateInfo.State -eq 'Running')
        Queued    = $writer.Queue.Count
        Written   = $writer.Status.Written
        Failed    = $writer.Status.Failed
        LastError = $writer.Status.LastError
        Capacity  = $script:CCFWriterCapacity
    }
}

function Wait-CCFLogWriter {
    <#
    .SYNOPSIS
        Waits until every log entry queued so far has been written to disk.

    .DESCRIPTION
        With Initialize-CCFLogger -Background, Write-CCFLog returns before the entry is in the
        file. Wait-CCFLogWriter blocks until every entry logged before the call is written,
        for example before reading or copying the log file, or before a step that may stop
        the process. The background writer keeps running. Without a background writer it
        returns at once. Write-CCFLog already waits by itself for ERROR and CRITICAL entries,
        Security and Audit records and entries logged with -NoBuffer.

    .PARAMETER TimeoutSeconds
        Longest wait. A warning is written when the entries are not written in time. Defaults to 30.

    .EXAMPLE
        Write-CCFLogInfo 'Report generated'; Wait-CCFLogWriter; Copy-Item (Get-CCFPath -Target Logs) \\server\logs -Recurse

        Makes sure the entry is in the file before the logs are copied.
    #>
    [CmdletBinding()]
    param(
        [ValidateRange(0, 3600)]
        [int]$TimeoutSeconds = 30
    )

    $writer = $script:CCFWriter
    if ($null -eq $writer) { return }

    $marker = [System.Threading.ManualResetEventSlim]::new($false)
    $queued = $false
    try { $queued = $writer.Queue.TryAdd($marker, $TimeoutSeconds * 1000) } catch { $queued = $false }
    if (-not $queued -or -not $marker.Wait([TimeSpan]::FromSeconds($TimeoutSeconds))) {
        Write-Warning "ArgosCCF: $($writer.Queue.Count) log entries were still waiting to be written after $TimeoutSeconds seconds."
    }
}

function Stop-CCFLogWriter {
    <#
    .SYNOPSIS
        Writes the queued log entries and stops the background writer; later entries are written directly.

    .DESCRIPTION
        Waits up to -TimeoutSeconds for the queued entries to be written, then stops the worker
        and frees it. Write-CCFLog then writes each entry before returning, as without
        -Background. It also runs by itself when PowerShell exits normally, when the module is
        removed or imported again, and when Initialize-CCFLogger runs without -Background.
        A warning is written when some entries could not be written.

    .PARAMETER TimeoutSeconds
        Longest wait for the queued entries. Entries still queued after it are lost, and a
        warning says how many. Defaults to 30.

    .EXAMPLE
        Stop-CCFLogWriter

        Writes what is queued and returns to direct writing.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Stops an in-memory worker of the current session; queued entries are written first.')]
    [CmdletBinding()]
    param(
        [ValidateRange(0, 3600)]
        [int]$TimeoutSeconds = 30
    )

    Close-CCFLogWriter -TimeoutSeconds $TimeoutSeconds
}

function Close-CCFLogWriter {
    <#
    .SYNOPSIS
        Writes the queued entries and stops the background writer (for Stop-CCFLogWriter, the exit handler and OnRemove).
    #>
    [CmdletBinding()]
    param(
        [int]$TimeoutSeconds = 30,
        [switch]$Exiting
    )

    $writer = $script:CCFWriter
    if ($null -eq $writer) { return }
    $script:CCFWriter = $null

    try { $writer.Queue.CompleteAdding() } catch { $null = $_ }
    $finished = $writer.Handle.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))
    $lost = $writer.Queue.Count
    if ($finished) {
        try { $null = $writer.PowerShell.EndInvoke($writer.Handle) } catch { $null = $_ }
    }
    else {
        $null = $writer.PowerShell.BeginStop($null, $null)
    }
    if ($lost -gt 0) { Write-Warning "ArgosCCF: $lost queued log entries were not written within $TimeoutSeconds seconds." }
    if ($writer.Status.Failed -gt 0) { Write-Warning "ArgosCCF: $($writer.Status.Failed) log entries could not be written. Last error: $($writer.Status.LastError)" }

    if ($finished) {
        $writer.PowerShell.Dispose()
        $writer.Runspace.Dispose()
        $writer.Queue.Dispose()
    }
    # Called from the PowerShell.Exiting handler, PowerShell removes the subscription itself
    # afterwards; removing it here makes the engine fail when it closes.
    if ($writer.ExitJob -and -not $Exiting) {
        Get-EventSubscriber -SourceIdentifier PowerShell.Exiting -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Action -eq $writer.ExitJob } | Unregister-Event -Force -ErrorAction SilentlyContinue
        Remove-Job -Job $writer.ExitJob -Force -ErrorAction SilentlyContinue
    }
}

# --- Level and providers ---

function Set-CCFLogLevel {
    <#
    .SYNOPSIS
        Sets the minimum level of the messages that are logged.

    .DESCRIPTION
        Messages below this level are ignored by Write-CCFLog and the level shortcuts. The order
        is DEBUG, INFO, WARN (SUCCESS has the same weight as WARN), ERROR, CRITICAL.
        The default level is INFO. The setting lasts for the current session.

    .PARAMETER Level
        The minimum level to log: DEBUG, INFO, WARN, ERROR or CRITICAL.

    .EXAMPLE
        Set-CCFLogLevel -Level DEBUG

        Logs everything, including Write-CCFLogDebug messages.

    .EXAMPLE
        Set-CCFLogLevel -Level ERROR

        Logs only errors and critical messages.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Changes an in-memory setting of the current session only.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL')]
        [string]$Level
    )

    $script:CurrentLogLevel = $script:LogLevels[$Level]
}

function Register-CCFLogProvider {
    <#
    .SYNOPSIS
        Sends log entries to your own script block instead of the default console output.

    .DESCRIPTION
        Once registered, Write-CCFLog calls the script block for every entry instead of writing
        it with Write-Host. The script block receives one hashtable argument with two keys:
        Entry (the log entry: Timestamp, Level, Category, Message, Data, Context) and Color.
        Use it to route logs to a UI module such as HermesConsoleUI. If the provider throws,
        the entry is written to the console instead. Log files are not affected.

    .PARAMETER ProviderScript
        Script block that receives @{ Entry = ...; Color = ... } for each log entry.

    .EXAMPLE
        Register-CCFLogProvider -ProviderScript {
            param($e)
            Write-ConsoleStatus -Message $e.Entry.Message -Type Info
        }

        Shows every log message with HermesConsoleUI.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ProviderScript
    )

    $script:LogProvider = $ProviderScript
    Write-CCFLog 'Log provider registered.' -Level 'SUCCESS'
}

function Register-CCFSIEMProvider {
    <#
    .SYNOPSIS
        Forwards every log entry to a script block, for example to send it to a SIEM.

    .DESCRIPTION
        After console output, Write-CCFLog calls the script block with one hashtable argument
        whose Entry key holds the log entry, with secrets already redacted. Errors in the
        provider are ignored so that logging never stops the script.

    .PARAMETER ProviderScript
        Script block that receives @{ Entry = ... } for each log entry.

    .EXAMPLE
        Register-CCFSIEMProvider -ProviderScript {
            param($e)
            $e.Entry | ConvertTo-Json -Compress | Add-Content -Path C:\siem\outbox.jsonl
        }

        Appends every entry, as JSON, to a file a SIEM agent collects.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ProviderScript
    )

    $script:SIEMProvider = $ProviderScript
    Write-CCFLog 'SIEM provider registered.' -Level 'SUCCESS'
}

# --- Health ---

function Test-CCFHealth {
    <#
    .SYNOPSIS
        Checks that the ArgosCCF components are loaded and that the Logs folder is writable.

    .DESCRIPTION
        Returns an object with Timestamp, Status ("OK" or "DEGRADED") and Checks, one entry per
        component (Logging, Configuration, Execution, Plugins), one for the Logs folder and,
        with background writing, one for the writer (running, with no failed writes).
        Status is DEGRADED when any check fails. Use it at the start of a script, or in a
        monitoring job, to fail early when the environment is not usable.

    .EXAMPLE
        (Test-CCFHealth).Status

        Returns "OK" when everything is available.

    .EXAMPLE
        Test-CCFHealth | Select-Object -ExpandProperty Checks | Where-Object { -not $_.Pass }

        Lists the checks that failed.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $report = [ordered]@{
        Timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Status    = 'OK'
        Checks    = @()
    }

    # One representative command per Core component.
    $components = [ordered]@{
        Logging       = 'Write-CCFLog'
        Configuration = 'Get-CCFConfig'
        Execution     = 'Invoke-CCFParallel'
        Plugins       = 'Invoke-CCFPlugin'
    }
    foreach ($name in $components.Keys) {
        $loaded = $null -ne (Get-Command -Name $components[$name] -ErrorAction SilentlyContinue)
        $report.Checks += @{ Target = "Component:$name"; Pass = $loaded }
        if (-not $loaded) { $report.Status = 'DEGRADED' }
    }

    $logsWritable = Test-CCFWritableDirectory -Path (Get-CCFPath -Target 'Logs')
    $report.Checks += @{ Target = 'LogsWritable'; Pass = $logsWritable }
    if (-not $logsWritable) { $report.Status = 'DEGRADED' }

    $writer = Get-CCFLogWriter
    if ($writer.Mode -eq 'Background') {
        $writerOk = $writer.Running -and $writer.Failed -eq 0
        $report.Checks += @{ Target = 'LogWriter'; Pass = $writerOk }
        if (-not $writerOk) { $report.Status = 'DEGRADED' }
    }

    return [PSCustomObject]$report
}

function Submit-CCFHeartbeat {
    <#
    .SYNOPSIS
        Records that the registered log provider is alive.

    .DESCRIPTION
        Stores the current time as the provider's last heartbeat. A UI or SIEM provider can call
        it periodically so that a host script can tell whether the provider is still active.

    .EXAMPLE
        Submit-CCFHeartbeat

        Records a heartbeat now.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Stores a timestamp in memory only.')]
    [CmdletBinding()]
    param()

    $script:LastProviderHeartbeat = Get-Date
}

# --- Logging ---

function Initialize-CCFLogger {
    <#
    .SYNOPSIS
        Sets the log file for the session and rotates it when it is too large.

    .DESCRIPTION
        Until this runs, Write-CCFLog writes System messages to the console only. Afterwards
        they also go to the given file in the Logs folder: the folder given with -Path, or
        Logs in the per-user data folder (see Get-CCFPath -Target Logs). Logs are never written
        into the folder the module is installed in, so updating the module keeps them.
        Before every write, a file larger than -MaxMB is renamed to .1 (older copies shift to
        .2, .3 and so on, keeping -MaxRolling files) and a new file is started; this applies to
        the session file and to the category files, and also when the logger starts.
        Messages with another category (Security, Audit, Errors...) always go to their own
        CCF_<Category>.log file in the same folder.

    .PARAMETER FileName
        Name of the log file, without a folder. Letters, digits, dot, dash and underscore only.
        Defaults to CCF_Session.log.

    .PARAMETER Path
        Folder for the log files of this session, for example your script's own logs folder.
        It is created if it does not exist; an error is thrown if it cannot be written.
        Without it, the per-user data folder is used.

    .PARAMETER MaxMB
        Size in MB above which the file is rotated. Defaults to 10.

    .PARAMETER MaxRolling
        Number of rotated files to keep. Defaults to 5.

    .PARAMETER JsonOutput
        Write each entry as one JSON object per line (including Data), instead of plain text.

    .PARAMETER Background
        Write log files from a background worker, so Write-CCFLog returns without waiting
        for the disk. Entries keep their order and are written in batches with the same lock
        and rotation. The queue holds 10,000 entries; when it is full, Write-CCFLog waits,
        so no entry is dropped. ERROR and CRITICAL entries, Security and Audit records and
        entries logged with -NoBuffer wait until they are in the file. The queue is written
        out when PowerShell exits normally, when the module is removed, by Stop-CCFLogWriter
        and when Initialize-CCFLogger runs again without -Background; entries still queued
        when the process is killed are lost. See Get-CCFLogWriter and Wait-CCFLogWriter.

    .EXAMPLE
        Initialize-CCFLogger -FileName 'Backup.log' -MaxMB 20

        Logs to Backup.log, rotated at 20 MB.

    .EXAMPLE
        Initialize-CCFLogger -JsonOutput

        Logs JSON lines to CCF_Session.log, for collection by a log shipper.

    .EXAMPLE
        Initialize-CCFLogger -Path (Join-Path $PSScriptRoot 'logs') -FileName 'Deploy.log'

        Writes this script's logs, and its Security and Audit records, next to the script.

    .EXAMPLE
        Initialize-CCFLogger -FileName 'Import.log' -Background

        Logs to Import.log from a background worker, for scripts that log many entries.
    #>
    [CmdletBinding()]
    param(
        [ValidateScript({ if (Test-CCFLogName -Name $_) { $true } else { throw "FileName must be a plain file name (letters, digits, '.', '-', '_'), not a path: $_" } })]
        [string]$FileName = 'CCF_Session.log',

        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [ValidateRange(1, 10240)]
        [int]$MaxMB = 10,

        [ValidateRange(1, 100)]
        [int]$MaxRolling = 5,

        [switch]$JsonOutput,

        [switch]$Background
    )

    # Entries queued under the previous settings are written first.
    if ($Background) { Wait-CCFLogWriter } else { Stop-CCFLogWriter }

    $script:JsonOutput = [bool]$JsonOutput
    $script:CCFSystemMeta = [ordered]@{
        Hostname = [Environment]::MachineName
        Version  = "$($MyInvocation.MyCommand.Module.Version)"
        Engine   = 'ArgosCCF'
    }

    if ($Path) {
        $folder = [System.IO.Path]::GetFullPath($PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path))
        if (-not (Test-CCFWritableDirectory -Path $folder)) { throw "The log folder cannot be created or written: $folder" }
        $script:LogsPathOverride = $folder
    }

    $logDir = Get-CCFPath -Target 'Logs'
    if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

    $script:CurrentLogFile = Join-Path $logDir $FileName
    $script:MaxLogSizeMB = $MaxMB
    $script:MaxLogRolling = $MaxRolling

    # The size is also checked before every write, so long sessions rotate too.
    Invoke-CCFLogRotation -Path $script:CurrentLogFile -MaxMB $MaxMB -MaxRolling $MaxRolling

    if ($Background) { Initialize-CCFLogWriter }
}

function Write-CCFLog {
    <#
    .SYNOPSIS
        Writes a log entry to the console, the registered providers and the log file.

    .DESCRIPTION
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

    .PARAMETER Message
        The message to log.

    .PARAMETER Level
        INFO (the default), SUCCESS, WARN, ERROR, CRITICAL or DEBUG.

    .PARAMETER Color
        Console color for INFO messages when no provider is registered. Defaults to White.

    .PARAMETER Data
        Optional structured data. It is redacted, passed to the providers and written to the
        file in JSON mode (Initialize-CCFLogger -JsonOutput).

    .PARAMETER Category
        Log category, which also names the log file. Letters, digits, dot, dash and underscore.
        Defaults to System.

    .PARAMETER NoBuffer
        With background writing (Initialize-CCFLogger -Background), wait until this entry is
        in the file before returning. Without background writing every entry is written
        before Write-CCFLog returns, so it has no effect.

    .EXAMPLE
        Write-CCFLog -Message 'Backup started' -Level INFO

        Logs an informational message.

    .EXAMPLE
        Write-CCFLog -Message 'Login failed' -Level WARN -Category Security -Data @{ User = 'admin' }

        Logs a warning to CCF_Security.log with the user name as data.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'The console is a log target; output must not mix with the pipeline.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowEmptyString()]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS', 'CRITICAL', 'DEBUG')]
        [string]$Level = 'INFO',

        [string]$Color = 'White',

        [hashtable]$Data = @{},

        [ValidateScript({ if (Test-CCFLogName -Name $_) { $true } else { throw "Category must contain only letters, digits, '.', '-' and '_': $_" } })]
        [string]$Category = 'System',

        [switch]$NoBuffer
    )

    if ($script:LogLevels[$Level] -lt $script:CurrentLogLevel) { return }

    $cleanMessage = ConvertTo-CCFLogText -Text (Protect-CCFSensitiveData -InputData $Message)
    $cleanData = Protect-CCFSensitiveData -InputData $Data
    $timestamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $rsId = if ($null -ne [runspace]::DefaultRunspace) { [runspace]::DefaultRunspace.Id } else { 1 }

    $logEntry = [ordered]@{
        Timestamp = $timestamp
        Level     = $Level
        Category  = $Category
        Message   = $cleanMessage
        Data      = $cleanData
        Context   = @{ RSID = $rsId }
    }
    $line = "[$timestamp] [$Level] [$Category] $cleanMessage"

    # 1. Console or UI provider
    if ($null -ne $script:LogProvider) {
        try {
            Invoke-Command -ScriptBlock $script:LogProvider -ArgumentList @{ Entry = $logEntry; Color = $Color } -ErrorAction Stop
        }
        catch {
            Write-Host "[FALLBACK] [$Level] $cleanMessage" -ForegroundColor Yellow
        }
    }
    else {
        $consoleColor = switch ($Level) {
            'SUCCESS' { 'Green' }
            'WARN' { 'Yellow' }
            'ERROR' { 'Red' }
            'CRITICAL' { 'Magenta' }
            'DEBUG' { 'Gray' }
            default { $Color }
        }
        Write-Host $line -ForegroundColor $consoleColor
    }

    # 2. SIEM export: failures are ignored so logging never stops the caller.
    if ($null -ne $script:SIEMProvider) {
        try {
            Invoke-Command -ScriptBlock $script:SIEMProvider -ArgumentList @{ Entry = $logEntry } -ErrorAction Stop
        }
        catch {
            Write-Verbose "SIEM provider failed: $($_.Exception.Message)"
        }
    }

    # 3. File
    $targetFile = $script:CurrentLogFile
    if ($Category -ne 'System') {
        $targetFile = Join-Path (Get-CCFPath -Target 'Logs') "CCF_${Category}.log"
    }

    if ($null -ne $targetFile) {
        $outMsg = if ($script:JsonOutput) { $logEntry | ConvertTo-Json -Depth 5 -Compress } else { $line }
        $text = $outMsg + [Environment]::NewLine

        # Background writing: queue the line; entries that must not be lost wait until they are on disk.
        # Audit and Security records, and errors, must not be lost without anyone noticing.
        $mustReport = $Category -eq 'Security' -or $Category -eq 'Audit' -or $script:LogLevels[$Level] -ge 3
        $queued = $false
        if ($null -ne $script:CCFWriter) {
            $writer = $script:CCFWriter
            $failedBefore = $writer.Status.Failed
            $queued = Add-CCFQueuedLogText -Path $targetFile -Text $text
            if ($queued -and ($NoBuffer -or $mustReport)) {
                Wait-CCFLogWriter -TimeoutSeconds 10
                if ($mustReport -and $writer.Status.Failed -gt $failedBefore) {
                    Write-Warning "ArgosCCF: a $Category $Level entry could not be written to ${targetFile}: $($writer.Status.LastError)"
                }
            }
        }
        if (-not $queued) {
            try {
                Add-CCFLogText -Path $targetFile -Text $text -MaxMB $script:MaxLogSizeMB -MaxRolling $script:MaxLogRolling
            }
            catch {
                # Never log a failure to log (it would recurse); warn on the console instead.
                $message = "Could not write to ${targetFile}: $($_.Exception.Message)"
                if ($mustReport) { Write-Warning "ArgosCCF: a $Category $Level entry was not saved. $message" }
                else { Write-Verbose $message }
            }
        }
    }
}

function Write-CCFErrorRecord {
    <#
    .SYNOPSIS
        Logs an error record from a catch block to CCF_Errors.log.

    .DESCRIPTION
        Writes the exception message at ERROR level in the Errors category, with the exception
        type and the script stack trace as data. Use it in catch blocks to keep a trace of
        failures without stopping the script.

    .PARAMETER ErrorRecord
        The error record, usually $_ inside a catch block.

    .PARAMETER Context
        Short text identifying where the error happened. Defaults to "General".

    .EXAMPLE
        try { Get-Item C:\missing -ErrorAction Stop } catch { Write-CCFErrorRecord -ErrorRecord $_ -Context 'Startup' }

        Logs "[Startup] Cannot find path ..." with the stack trace.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [string]$Context = 'General'
    )

    $data = [ordered]@{ Exception = $ErrorRecord.Exception.GetType().Name; StackTrace = $ErrorRecord.ScriptStackTrace }
    Write-CCFLog -Message "[$Context] $($ErrorRecord.Exception.Message)" -Level 'ERROR' -Category 'Errors' -Data $data
}

function Write-CCFLogInfo {
    <#
    .SYNOPSIS
        Logs a message at INFO level.

    .DESCRIPTION
        Shortcut for Write-CCFLog -Level INFO. The alias Log-Info is kept for older scripts.
        Message and Data can be passed by position.

    .PARAMETER Message
        The message to log.

    .PARAMETER Data
        Optional structured data, redacted before it is logged.

    .EXAMPLE
        Write-CCFLogInfo 'Configuration loaded'

        Logs an informational message.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)][AllowEmptyString()][string]$Message,
        [Parameter(Position = 1)][hashtable]$Data = @{}
    )
    Write-CCFLog $Message -Level 'INFO' -Data $Data
}

function Write-CCFLogSuccess {
    <#
    .SYNOPSIS
        Logs a message at SUCCESS level.

    .DESCRIPTION
        Shortcut for Write-CCFLog -Level SUCCESS, shown in green on the console. The alias
        Log-Success is kept for older scripts. Message and Data can be passed by position.

    .PARAMETER Message
        The message to log.

    .PARAMETER Data
        Optional structured data, redacted before it is logged.

    .EXAMPLE
        Write-CCFLogSuccess 'Backup completed'

        Logs a success message.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)][AllowEmptyString()][string]$Message,
        [Parameter(Position = 1)][hashtable]$Data = @{}
    )
    Write-CCFLog $Message -Level 'SUCCESS' -Data $Data
}

function Write-CCFLogWarn {
    <#
    .SYNOPSIS
        Logs a message at WARN level.

    .DESCRIPTION
        Shortcut for Write-CCFLog -Level WARN, shown in yellow on the console. The alias
        Log-Warn is kept for older scripts. Message and Data can be passed by position.

    .PARAMETER Message
        The message to log.

    .PARAMETER Data
        Optional structured data, redacted before it is logged.

    .EXAMPLE
        Write-CCFLogWarn 'Disk space below 10%' @{ Drive = 'C:' }

        Logs a warning with the drive as data.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)][AllowEmptyString()][string]$Message,
        [Parameter(Position = 1)][hashtable]$Data = @{}
    )
    Write-CCFLog $Message -Level 'WARN' -Data $Data
}

function Write-CCFLogError {
    <#
    .SYNOPSIS
        Logs a message at ERROR level.

    .DESCRIPTION
        Shortcut for Write-CCFLog -Level ERROR, shown in red on the console. It only logs: it
        does not write to the error stream or stop the script. The alias Log-Error is kept for
        older scripts. Message and Data can be passed by position.

    .PARAMETER Message
        The message to log.

    .PARAMETER Data
        Optional structured data, redacted before it is logged.

    .EXAMPLE
        Write-CCFLogError 'Could not reach the database'

        Logs an error message.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)][AllowEmptyString()][string]$Message,
        [Parameter(Position = 1)][hashtable]$Data = @{}
    )
    Write-CCFLog $Message -Level 'ERROR' -Data $Data
}

function Write-CCFLogCritical {
    <#
    .SYNOPSIS
        Logs a message at CRITICAL level.

    .DESCRIPTION
        Shortcut for Write-CCFLog -Level CRITICAL, shown in magenta on the console, for
        failures that need immediate attention. The alias Log-Critical is kept for older
        scripts. Message and Data can be passed by position.

    .PARAMETER Message
        The message to log.

    .PARAMETER Data
        Optional structured data, redacted before it is logged.

    .EXAMPLE
        Write-CCFLogCritical 'Security policy could not be applied'

        Logs a critical message.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)][AllowEmptyString()][string]$Message,
        [Parameter(Position = 1)][hashtable]$Data = @{}
    )
    Write-CCFLog $Message -Level 'CRITICAL' -Data $Data
}

function Write-CCFLogDebug {
    <#
    .SYNOPSIS
        Logs a message at DEBUG level.

    .DESCRIPTION
        Shortcut for Write-CCFLog -Level DEBUG. Debug messages are only logged after
        Set-CCFLogLevel -Level DEBUG. The alias Log-Debug is kept for older scripts.
        Message and Data can be passed by position.

    .PARAMETER Message
        The message to log.

    .PARAMETER Data
        Optional structured data, redacted before it is logged.

    .EXAMPLE
        Set-CCFLogLevel -Level DEBUG; Write-CCFLogDebug 'Cache hit for ccf_core'

        Logs a debug message.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)][AllowEmptyString()][string]$Message,
        [Parameter(Position = 1)][hashtable]$Data = @{}
    )
    Write-CCFLog $Message -Level 'DEBUG' -Data $Data
}

function Write-CCFLogHeader {
    <#
    .SYNOPSIS
        Logs a section header at INFO level, shown in cyan.

    .DESCRIPTION
        Shortcut for Write-CCFLog -Level INFO -Color Cyan, to mark the start of a phase of a
        script in the log. The alias Log-Header is kept for older scripts.

    .PARAMETER Message
        The header text.

    .EXAMPLE
        Write-CCFLogHeader 'Phase 2: applying settings'

        Logs the header.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)][AllowEmptyString()][string]$Message
    )
    Write-CCFLog $Message -Level 'INFO' -Color 'Cyan'
}

# --- Security and audit records ---

function Write-CCFSecurityRecord {
    <#
    .SYNOPSIS
        Records a security event, such as an attack attempt or a blocked action, in CCF_Security.log.

    .DESCRIPTION
        Logs "[SECURITY] <Type> from <Source>" in the Security category, with the type, source,
        payload and metadata as data (redacted like any other log data). Use it when the
        script detects or blocks something suspicious. The alias Log-Attack is kept for older
        scripts.

    .PARAMETER Type
        Kind of event, for example PathTraversal or BruteForce.

    .PARAMETER Source
        Where it came from, for example an IP address or an input name.

    .PARAMETER Payload
        Optional offending value. It is logged as data, after redaction.

    .PARAMETER Severity
        WARN (the default), ERROR or CRITICAL.

    .PARAMETER Metadata
        Optional extra data.

    .EXAMPLE
        Write-CCFSecurityRecord -Type 'PathTraversal' -Source 'UserInput' -Payload '../../etc/passwd'

        Records a blocked path traversal attempt.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Type,
        [Parameter(Mandatory = $true)][string]$Source,
        [string]$Payload = '',
        [ValidateSet('WARN', 'ERROR', 'CRITICAL')][string]$Severity = 'WARN',
        [hashtable]$Metadata = @{}
    )

    $data = @{ Type = $Type; Source = $Source; Payload = $Payload; Metadata = $Metadata }
    Write-CCFLog -Message "[SECURITY] $Type from $Source" -Level $Severity -Category 'Security' -Data $data
}

function Write-CCFAuditRecord {
    <#
    .SYNOPSIS
        Records who did what, on which resource, in CCF_Audit.log.

    .DESCRIPTION
        Logs "[AUDIT] <User> <Action> <Resource>" at INFO level in the Audit category, with the
        outcome and metadata as data. Use it for actions that must be traceable, such as
        deletions or configuration changes. The alias Log-Audit is kept for older scripts.

    .PARAMETER Action
        What was done, for example FileDeletion.

    .PARAMETER User
        Who did it.

    .PARAMETER Resource
        Optional target of the action, for example a file path.

    .PARAMETER Outcome
        Success (the default) or Failure.

    .PARAMETER Metadata
        Optional extra data.

    .EXAMPLE
        Write-CCFAuditRecord -Action 'FileDeletion' -User $env:USERNAME -Resource 'C:\Data\db.bak'

        Records that the current user deleted the file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Action,
        [Parameter(Mandatory = $true)][string]$User,
        [string]$Resource = '',
        [ValidateSet('Success', 'Failure')][string]$Outcome = 'Success',
        [hashtable]$Metadata = @{}
    )

    $data = @{ Action = $Action; User = $User; Resource = $Resource; Outcome = $Outcome; Metadata = $Metadata }
    Write-CCFLog -Message ("[AUDIT] $User $Action $Resource".Trim()) -Level 'INFO' -Category 'Audit' -Data $data
}

# --- Log maintenance ---

function Remove-CCFOldLog {
    <#
    .SYNOPSIS
        Deletes log files older than -DaysToKeep from the Logs folder, optionally zipping them first.

    .DESCRIPTION
        Finds *.log files (and rotated *.log.N files) in the Logs folder whose last write is older
        than -DaysToKeep days, optionally compresses them into CCF_Archive_<date>.zip in the same
        folder, deletes them and returns their names. Supports -WhatIf and -Confirm.
        The alias Remove-OldCCFLogs is kept for older scripts.

    .PARAMETER DaysToKeep
        Age in days of the newest files to keep. Defaults to 30.

    .PARAMETER CompressBeforeDelete
        Zip the files before deleting them. If compressing is declined or fails, nothing is deleted.

    .EXAMPLE
        Remove-CCFOldLog -DaysToKeep 30 -CompressBeforeDelete

        Archives and deletes logs older than 30 days.

    .EXAMPLE
        Remove-CCFOldLog -DaysToKeep 7 -WhatIf

        Shows which logs would be deleted.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([string[]])]
    param(
        [ValidateRange(0, 3650)][int]$DaysToKeep = 30,
        [switch]$CompressBeforeDelete
    )

    $logDir = Get-CCFPath -Target 'Logs'
    if (-not (Test-Path -LiteralPath $logDir)) { return [string[]]@() }

    $cutoff = (Get-Date).AddDays(-$DaysToKeep)
    $oldFiles = @(Get-ChildItem -LiteralPath $logDir -File |
            Where-Object { $_.Name -match '\.log(\.\d+)?$' -and $_.LastWriteTime -lt $cutoff })
    if ($oldFiles.Count -eq 0) { return [string[]]@() }

    if ($CompressBeforeDelete) {
        # The files are only deleted once they are safely in the archive: if compressing is declined
        # or fails, nothing is deleted.
        if (-not $PSCmdlet.ShouldProcess($logDir, "Compress $($oldFiles.Count) log file(s)")) {
            if (-not $WhatIfPreference) { return [string[]]@() }
        }
        else {
            $archive = Join-Path $logDir ('CCF_Archive_{0}.zip' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
            try { Compress-Archive -LiteralPath $oldFiles.FullName -DestinationPath $archive -Force -ErrorAction Stop }
            catch {
                Write-CCFLogError "Old logs were not deleted because they could not be compressed: $($_.Exception.Message)"
                return [string[]]@()
            }
        }
    }

    $removed = foreach ($file in $oldFiles) {
        if ($PSCmdlet.ShouldProcess($file.FullName, 'Delete')) {
            Remove-Item -LiteralPath $file.FullName -Force
            $file.Name
        }
    }
    return [string[]]@($removed)
}

# Names from earlier versions, kept so existing scripts keep working.
New-Alias -Name Log-Info -Value Write-CCFLogInfo
New-Alias -Name Log-Success -Value Write-CCFLogSuccess
New-Alias -Name Log-Warn -Value Write-CCFLogWarn
New-Alias -Name Log-Error -Value Write-CCFLogError
New-Alias -Name Log-Critical -Value Write-CCFLogCritical
New-Alias -Name Log-Debug -Value Write-CCFLogDebug
New-Alias -Name Log-Header -Value Write-CCFLogHeader
New-Alias -Name Log-Attack -Value Write-CCFSecurityRecord
New-Alias -Name Log-Audit -Value Write-CCFAuditRecord
New-Alias -Name Init-CCFLogger -Value Initialize-CCFLogger
New-Alias -Name Catch-CCFError -Value Write-CCFErrorRecord
New-Alias -Name Redact-CCFSensitiveData -Value Protect-CCFSensitiveData
New-Alias -Name Test-CCFHighEntropy -Value Test-CCFEntropyContent
New-Alias -Name Remove-OldCCFLogs -Value Remove-CCFOldLog
