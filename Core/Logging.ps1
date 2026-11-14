# ArgosCCF logging engine.
#
# Writes log entries to the console (or a registered provider), to a SIEM provider and to log
# files, after redacting secrets. Also provides security and audit records, log rotation and
# clean-up, and a health check.

$script:LogProvider = $null
$script:SIEMProvider = $null
$script:CurrentLogFile = $null
$script:MaxLogSizeMB = 10
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

function Get-CCFSecretsRegex {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return '(?i)(password|passwd|pwd|token|api_key|secret|authorization|auth_token|apikey)'
}

function Invoke-CCFEntropyScan {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$InputString)

    if ([string]::IsNullOrEmpty($InputString)) { return '' }
    $words = $InputString -split '\s+'
    $newWords = foreach ($word in $words) {
        $cleanWord = $word -replace '[,;.:]$', ''
        if (Test-CCFEntropyContent -String $cleanWord) { '[REDACTED-ENTROPY]' } else { $word }
    }
    return ($newWords -join ' ')
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

# --- Redaction ---

function Test-CCFEntropyContent {
    <#
    .SYNOPSIS
        Tests whether a string looks like a secret, such as an API key or a token.

    .DESCRIPTION
        Returns $true for strings of 20 or more characters without spaces or path characters
        that mix at least three kinds of characters (upper case, lower case, digits, - _ + =),
        or two kinds when longer than 32 characters. Protect-CCFSensitiveData uses it to
        redact values that are not labeled as secrets. It is a heuristic: it can miss secrets
        and flag harmless identifiers.

    .PARAMETER String
        The text to test.

    .EXAMPLE
        Test-CCFEntropyContent -String 'AKIA-872H-J92K-LL92-MM102-PP01'

        Returns $true.

    .EXAMPLE
        Test-CCFEntropyContent -String 'C:\Windows\System32'

        Returns $false: paths are not treated as secrets.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$String
    )

    if ([string]::IsNullOrEmpty($String) -or $String.Length -lt 20 -or $String -match '\s') { return $false }
    if ($String -match '[\\/:]') { return $false }

    $typeCount = 0
    if ($String -cmatch '[A-Z]') { $typeCount++ }
    if ($String -cmatch '[a-z]') { $typeCount++ }
    if ($String -match '[0-9]') { $typeCount++ }
    if ($String -match '[-_+=]') { $typeCount++ }

    return ($typeCount -ge 3 -or ($typeCount -ge 2 -and $String.Length -gt 32))
}

function Protect-CCFSensitiveData {
    <#
    .SYNOPSIS
        Returns a copy of the data with passwords, tokens and other secrets replaced by [REDACTED].

    .DESCRIPTION
        Strings: "password=...", "token: ..." and similar pairs are replaced by "password=[REDACTED]",
        and words that look like secrets (see Test-CCFEntropyContent) by "[REDACTED-ENTROPY]".
        Hashtables and objects: values whose key names a secret (password, token, secret,
        apikey, authorization...) or that look like secrets are replaced by "[REDACTED]", and
        nested hashtables and objects are processed too. Values nested more than five levels
        deep are replaced by "[DEPTH-LIMIT]" instead of being logged unchecked.
        The input is not modified. Write-CCFLog applies this to every message and its data.

    .PARAMETER InputData
        A string, hashtable or object to redact. Other types are returned unchanged.

    .PARAMETER Depth
        Current nesting level, used internally for recursion. Leave it at 0.

    .EXAMPLE
        Protect-CCFSensitiveData -InputData 'login user=admin password=Secr3t!'

        Returns "login user=admin password=[REDACTED]".

    .EXAMPLE
        Protect-CCFSensitiveData -InputData @{ User = 'admin'; ApiKey = 'abc' }

        Returns a hashtable where ApiKey is "[REDACTED]".
    #>
    [CmdletBinding()]
    [OutputType([string], [hashtable], [pscustomobject], [object])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [object]$InputData,

        [int]$Depth = 0
    )

    if ($null -eq $InputData) { return $InputData }
    if ($Depth -gt 5) { return '[DEPTH-LIMIT]' }

    $secretsRegex = Get-CCFSecretsRegex
    $isHashtable = $InputData -is [System.Collections.IDictionary]
    $isCustomObject = $InputData -is [System.Management.Automation.PSCustomObject]

    if ($InputData -is [string]) {
        $text = $InputData -replace "$secretsRegex\s*[:=]\s*(\S+)", '$1=[REDACTED]'
        if ($text.Length -lt 2000) { return (Invoke-CCFEntropyScan -InputString $text) }
        return $text
    }

    if ($isHashtable -or $isCustomObject) {
        # Ordered output keeps hashtables and objects in their original key order.
        $newData = [ordered]@{}
        $props = if ($isHashtable) { @($InputData.Keys) } else { $InputData.PSObject.Properties.Name }

        foreach ($prop in $props) {
            $val = if ($isHashtable) { $InputData[$prop] } else { $InputData.$prop }

            $isSecret = [string]$prop -match $secretsRegex
            if ($val -is [string] -and (Test-CCFEntropyContent -String $val)) { $isSecret = $true }

            if ($isSecret) {
                $newData[$prop] = '[REDACTED]'
            }
            elseif ($Depth -ge 5 -and $null -ne $val) {
                # Values nested deeper than five levels are not inspected, and not logged either.
                $newData[$prop] = '[DEPTH-LIMIT]'
            }
            elseif ($val -is [System.Collections.IDictionary] -or $val -is [System.Management.Automation.PSCustomObject]) {
                $newData[$prop] = Protect-CCFSensitiveData -InputData $val -Depth ($Depth + 1)
            }
            elseif ($val -is [string]) {
                $newData[$prop] = Protect-CCFSensitiveData -InputData $val -Depth ($Depth + 1)
            }
            else {
                $newData[$prop] = $val
            }
        }

        if ($isHashtable) {
            $result = @{}
            foreach ($key in $newData.Keys) { $result[$key] = $newData[$key] }
            return $result
        }
        return [PSCustomObject]$newData
    }

    return $InputData
}

# --- Health ---

function Test-CCFHealth {
    <#
    .SYNOPSIS
        Checks that the ArgosCCF components are loaded and that the Logs folder is writable.

    .DESCRIPTION
        Returns an object with Timestamp, Status ("OK" or "DEGRADED") and Checks, one entry per
        component (Logging, Configuration, Execution, Plugins) and one for the Logs folder.
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
        they also go to the given file in the Logs folder (see Get-CCFPath -Target Logs).
        If the file is larger than -MaxMB, it is renamed to .1 (older copies shift to .2, .3
        and so on, keeping -MaxRolling files) and a new file is started.
        Messages with another category (Security, Audit, Errors...) always go to their own
        CCF_<Category>.log file in the same folder.

    .PARAMETER FileName
        Name of the log file, without a folder. Letters, digits, dot, dash and underscore only.
        Defaults to CCF_Session.log.

    .PARAMETER MaxMB
        Size in MB above which the file is rotated. Defaults to 10.

    .PARAMETER MaxRolling
        Number of rotated files to keep. Defaults to 5.

    .PARAMETER JsonOutput
        Write each entry as one JSON object per line (including Data), instead of plain text.

    .EXAMPLE
        Initialize-CCFLogger -FileName 'Backup.log' -MaxMB 20

        Logs to Backup.log, rotated at 20 MB.

    .EXAMPLE
        Initialize-CCFLogger -JsonOutput

        Logs JSON lines to CCF_Session.log, for collection by a log shipper.
    #>
    [CmdletBinding()]
    param(
        [ValidateScript({ if (Test-CCFLogName -Name $_) { $true } else { throw "FileName must be a plain file name (letters, digits, '.', '-', '_'), not a path: $_" } })]
        [string]$FileName = 'CCF_Session.log',

        [ValidateRange(1, 10240)]
        [int]$MaxMB = 10,

        [ValidateRange(1, 100)]
        [int]$MaxRolling = 5,

        [switch]$JsonOutput
    )

    $script:JsonOutput = [bool]$JsonOutput
    $script:CCFSystemMeta = [ordered]@{
        Hostname = [Environment]::MachineName
        Version  = "$($MyInvocation.MyCommand.Module.Version)"
        Engine   = 'ArgosCCF'
    }

    $logDir = Get-CCFPath -Target 'Logs'
    if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

    $script:CurrentLogFile = Join-Path $logDir $FileName
    $script:MaxLogSizeMB = $MaxMB

    if (Test-Path -LiteralPath $script:CurrentLogFile) {
        $size = (Get-Item -LiteralPath $script:CurrentLogFile).Length / 1MB
        if ($size -gt $script:MaxLogSizeMB) {
            for ($i = $MaxRolling - 1; $i -ge 1; $i--) {
                $old = "$($script:CurrentLogFile).$i"
                $new = "$($script:CurrentLogFile).$($i + 1)"
                if (Test-Path -LiteralPath $old) { Move-Item -LiteralPath $old -Destination $new -Force }
            }
            Move-Item -LiteralPath $script:CurrentLogFile -Destination "$($script:CurrentLogFile).1" -Force
        }
    }
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
        Kept for compatibility; entries are always written immediately.

    .EXAMPLE
        Write-CCFLog -Message 'Backup started' -Level INFO

        Logs an informational message.

    .EXAMPLE
        Write-CCFLog -Message 'Login failed' -Level WARN -Category Security -Data @{ User = 'admin' }

        Logs a warning to CCF_Security.log with the user name as data.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'The console is a log target; output must not mix with the pipeline.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'NoBuffer', Justification = 'Kept so existing scripts that pass it keep working.')]
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
        try {
            $parent = Split-Path $targetFile -Parent
            if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
            $outMsg | Out-File -LiteralPath $targetFile -Append -Encoding UTF8 -ErrorAction Stop
        }
        catch {
            # Never log a failure to log: it would recurse.
            Write-Verbose "Could not write to ${targetFile}: $($_.Exception.Message)"
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
        Zip the files before deleting them.

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

    if ($CompressBeforeDelete -and $PSCmdlet.ShouldProcess($logDir, "Compress $($oldFiles.Count) log file(s)")) {
        $archive = Join-Path $logDir ('CCF_Archive_{0}.zip' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
        Compress-Archive -LiteralPath $oldFiles.FullName -DestinationPath $archive -Force
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
