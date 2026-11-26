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
# Initialize-CCFLogger -Strict: chained, Security and Audit entries that cannot be written throw an error.
$script:CCFStrict = $false

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

# The lock of a log file can be opened by every account: a program that runs as administrator and the same program
# without elevation write the same files, and a lock created by one with the default permissions would shut the other out.
$script:CCFMutexSecurity = $null

function Get-CCFFileMutex {
    <#
    .SYNOPSIS
        The named mutex that serializes writes to one log file, or $null when it cannot be opened (the text is then
        written without it, as when the lock times out).
    #>
    [CmdletBinding()]
    [OutputType([System.Threading.Mutex])]
    param([Parameter(Mandatory = $true)][string]$Path)

    $name = Get-CCFFileMutexName -Path $Path
    if ($IsLinux -or $IsMacOS) { return [System.Threading.Mutex]::new($false, $name) }
    # The types are looked up by name: MutexAcl exists only in PowerShell 7, the constructor with permissions only in 5.1.
    $acl = 'System.Threading.MutexAcl' -as [type]
    $rightsType = 'System.Security.AccessControl.MutexRights' -as [type]
    $useRights = [Enum]::Parse($rightsType, 'Synchronize, Modify')
    if ($null -eq $script:CCFMutexSecurity) {
        $security = New-Object -TypeName 'System.Security.AccessControl.MutexSecurity'
        foreach ($sid in 'S-1-5-18', 'S-1-5-32-544', 'S-1-5-11') {
            $rights = if ($sid -eq 'S-1-5-11') { $useRights } else { [Enum]::Parse($rightsType, 'FullControl') }
            $rule = New-Object -TypeName 'System.Security.AccessControl.MutexAccessRule' -ArgumentList ([System.Security.Principal.SecurityIdentifier]::new($sid)), $rights, 'Allow'
            $security.AddAccessRule($rule)
        }
        $script:CCFMutexSecurity = $security
    }
    $created = $false
    try {
        if ($null -ne $acl) { return $acl::Create($false, $name, [ref]$created, $script:CCFMutexSecurity) }
        return New-Object -TypeName 'System.Threading.Mutex' -ArgumentList $false, $name, ([ref]$created), $script:CCFMutexSecurity
    }
    catch {
        # Created earlier with other permissions: open it with only what writing needs.
        $existing = $null
        try {
            $opened = if ($null -ne $acl) { $acl::TryOpenExisting($name, $useRights, [ref]$existing) } else { [System.Threading.Mutex]::TryOpenExisting($name, $useRights, [ref]$existing) }
            if ($opened) { return $existing }
        }
        catch { Write-Verbose "The lock of $Path cannot be opened: $($_.Exception.Message)" }
        return $null
    }
}

function Invoke-CCFLogRotation {
    <#
    .SYNOPSIS
        Renames a log file to .1 (shifting older copies, keeping MaxRolling of them) when it is larger than MaxMB.
    .DESCRIPTION
        Uses .NET calls only, so the background writer can run it without loading cmdlets.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$MaxMB = 10,
        [int]$MaxRolling = 5,
        # Chained log: before the oldest copy is deleted, returns the line that records it (see Add-CCFLogText).
        [switch]$Chain
    )

    $info = [System.IO.FileInfo]::new($Path)
    if (-not $info.Exists -or $info.Length -le ([long]$MaxMB * 1MB)) { return }

    $archived = $null
    $oldest = "$Path.$MaxRolling"
    if ($Chain -and [System.IO.File]::Exists($oldest)) { $archived = Get-CCFArchiveLine -Path $oldest }

    for ($i = $MaxRolling - 1; $i -ge 0; $i--) {
        $old = if ($i -eq 0) { $Path } else { "$Path.$i" }
        $new = "$Path.$($i + 1)"
        if (-not [System.IO.File]::Exists($old)) { continue }
        if ([System.IO.File]::Exists($new)) { [System.IO.File]::Delete($new) }
        [System.IO.File]::Move($old, $new)
    }
    if ($archived) { return $archived }
}

function Add-CCFLogText {
    <#
    .SYNOPSIS
        Appends text (one or more complete lines) to a log file, rotating it first if needed, with the file locked for every runspace and process.
    .DESCRIPTION
        With -Chain, returns the chain hash of the last line written.
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
        [int]$MaxRolling = 5,
        [switch]$Chain,
        [string]$ChainId = ''
    )

    $mutex = Get-CCFFileMutex -Path $Path
    $locked = $false
    try {
        if ($null -ne $mutex) {
            try { $locked = $mutex.WaitOne(5000) }
            catch [System.Threading.AbandonedMutexException] { $locked = $true }
        }
        if (-not $locked) { Write-Verbose "No lock on $Path; writing anyway." }

        $archived = Invoke-CCFLogRotation -Path $Path -MaxMB $MaxMB -MaxRolling $MaxRolling -Chain:$Chain
        # Chained logs: the hash is computed inside the lock, from the line the file really ends with. When rotation
        # deleted the oldest copy, the first line of the new file says so, so the chain can still be checked.
        $head = $null
        if ($Chain) {
            if ($archived) { $Text = $archived + [Environment]::NewLine + $Text }
            $Text = Add-CCFChainToText -Path $Path -Text $Text -ChainId $ChainId
            $head = Split-CCFChainLine -Line (($Text.TrimEnd() -split "`r?`n")[-1])
        }
        for ($attempt = 1; $attempt -le 5; $attempt++) {
            try {
                [System.IO.File]::AppendAllText($Path, $Text, $script:CCFLogEncoding)
                if ($head) { return $head.Hash }
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
        if ($null -ne $mutex) { $mutex.Dispose() }
    }
}

# --- Tamper-evident logs ---
#
# With Initialize-CCFLogger -Chain, every line of the chained categories ends with the SHA-256 of the previous
# line's hash and its own text: " #chain=<hex>" in text mode, a "Chain" property in JSON mode. Changing,
# inserting or deleting a line breaks every hash after it (Test-CCFLogChain). Deleting the last lines cannot be
# seen from the file alone: keep the last hash somewhere else (Get-CCFLogChainHead) to cover that.

$script:CCFChainGenesis = '0' * 64
$script:CCFChainCategories = @()
# Who writes the chain (Initialize-CCFLogger -ChainId). It is part of the hashed text of every line.
$script:CCFChainId = ''
# Called with every new chain head (Register-CCFChainAnchor), to keep it where the log's writer cannot change it.
$script:CCFChainAnchor = $null
$script:CCFChainAnchorSeconds = 0
$script:CCFChainAnchorLast = @{}
$script:CCFChainAnchorFailures = 0

function Get-CCFChainHash {
    <#
    .SYNOPSIS
        SHA-256 (lowercase hex) of the previous hash followed by the line, as used by the log chain.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][string]$Previous,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Line
    )
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return [System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Previous + $Line))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Split-CCFChainLine {
    <#
    .SYNOPSIS
        Separates a log line into the text that was hashed and its chain hash ($null when the line has none).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Line)
    $m = [regex]::Match($Line, ' #chain=([0-9a-f]{64})$')
    if ($m.Success) { return [pscustomobject]@{ Text = $Line.Substring(0, $m.Index); Hash = $m.Groups[1].Value } }
    $m = [regex]::Match($Line, ',"Chain":"([0-9a-f]{64})"\}$')
    if ($m.Success) { return [pscustomobject]@{ Text = $Line.Substring(0, $m.Index) + '}'; Hash = $m.Groups[1].Value } }
    return [pscustomobject]@{ Text = $Line; Hash = $null }
}

# When rotation deletes the oldest copy of a chained log, the new file starts with a line that records the
# last hash and the time of the last line of the deleted copy. It is chained like any other line.
# Only lines of the Chain category count: the same words inside the message of another entry are ignored.
$script:CCFArchiveRegex = [regex]'(?m)^(?:\[[0-9T:.Z-]+\] \[INFO\] \[Chain\] |\{"Timestamp":"[0-9T:.Z-]+","Level":"INFO","Category":"Chain","Message":")\[CHAIN\] Archived (?<file>\S+): (?<lines>\d+) lines up to (?<time>\S+), last hash (?<hash>[0-9a-f]{64})'

function Get-CCFLineTime {
    <#
    .SYNOPSIS
        Time of a log line (text or JSON), or $null.
    #>
    [CmdletBinding()]
    [OutputType([datetime])]
    param([AllowEmptyString()][string]$Line)
    $m = [regex]::Match($Line, '^\[(\d{4}-\d{2}-\d{2}T[0-9:.]+Z)\]|"Timestamp":"(\d{4}-\d{2}-\d{2}T[0-9:.]+Z)"')
    if (-not $m.Success) { return $null }
    $value = if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value }
    return [datetime]::Parse($value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)
}

function Get-CCFArchiveLine {
    <#
    .SYNOPSIS
        The line that records the deletion of a rotated copy of a chained log, or $null when it has no chained lines.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Path)
    $last = $null; $count = 0
    foreach ($line in [System.IO.File]::ReadAllLines($Path, [System.Text.Encoding]::UTF8)) {
        $part = Split-CCFChainLine -Line $line
        if ($part.Hash) { $last = $part; $count++ }
    }
    if (-not $last) { return $null }
    $time = Get-CCFLineTime -Line $last.Text
    $when = if ($time) { $time.ToString('yyyy-MM-ddTHH:mm:ss.fffZ') } else { 'unknown' }
    $message = "[CHAIN] Archived $([System.IO.Path]::GetFileName($Path)): $count lines up to $when, last hash $($last.Hash)"
    $timestamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    if ($script:JsonOutput) { return ([ordered]@{ Timestamp = $timestamp; Level = 'INFO'; Category = 'Chain'; Message = $message } | ConvertTo-Json -Compress) }
    return "[$timestamp] [INFO] [Chain] $message"
}

function Get-CCFChainLineId {
    <#
    .SYNOPSIS
        The writer identifier of a chained line (its text without the hash), or '' when it has none.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)
    $m = [regex]::Match($Text, ' #id=([A-Za-z0-9._-]{1,64})$')
    if (-not $m.Success) { $m = [regex]::Match($Text, ',"ChainId":"([A-Za-z0-9._-]{1,64})"\}$') }
    if ($m.Success) { return $m.Groups[1].Value }
    return ''
}

function Get-CCFLastChainHash {
    <#
    .SYNOPSIS
        Chain hash of the last chained line of a log, of its newest rotated copy when the log is new, or the
        all-zero start value.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        # Receives the text of that line, without its hash.
        [ref]$LineText
    )
    foreach ($file in @($Path, "$Path.1")) {
        if (-not [System.IO.File]::Exists($file)) { continue }
        $stream = [System.IO.File]::Open($file, 'Open', 'Read', 'ReadWrite')
        try {
            $length = [Math]::Min($stream.Length, 65536)
            if ($length -eq 0) { continue }
            $null = $stream.Seek(-$length, 'End')
            $buffer = New-Object byte[] $length
            $null = $stream.Read($buffer, 0, $length)
        }
        finally { $stream.Dispose() }
        $lines = [System.Text.Encoding]::UTF8.GetString($buffer) -split "`r?`n"
        for ($i = $lines.Count - 1; $i -ge 0; $i--) {
            $part = Split-CCFChainLine -Line $lines[$i]
            if ($part.Hash) {
                if ($LineText) { $LineText.Value = $part.Text }
                return $part.Hash
            }
        }
    }
    return $script:CCFChainGenesis
}

function Add-CCFChainToText {
    <#
    .SYNOPSIS
        Adds the chain hash to each line of Text, starting from the last hash of the file. Runs inside the file
        lock (Add-CCFLogText -Chain), so concurrent writers chain in the order they write.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text,
        [string]$ChainId = ''
    )
    $previous = Get-CCFLastChainHash -Path $Path
    $out = [System.Text.StringBuilder]::new()
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -eq '') { continue }
        if ($ChainId) {
            if ($line.StartsWith('{') -and $line.EndsWith('}')) { $line = $line.Substring(0, $line.Length - 1) + ",""ChainId"":""$ChainId""}" }
            else { $line = "$line #id=$ChainId" }
        }
        $hash = Get-CCFChainHash -Previous $previous -Line $line
        $chained = if ($line.StartsWith('{') -and $line.EndsWith('}')) { $line.Substring(0, $line.Length - 1) + ",""Chain"":""$hash""}" } else { "$line #chain=$hash" }
        $null = $out.Append($chained).Append([Environment]::NewLine)
        $previous = $hash
    }
    return $out.ToString()
}

function Register-CCFChainAnchor {
    <#
    .SYNOPSIS
        Runs a script block with every new chain head, to save it where the program that writes the log cannot change it.

    .DESCRIPTION
        After each line of a chained category is written (Initialize-CCFLogger -Chain), the script block receives an
        object with Path, Category, Hash, ChainId and Time (UTC). Save it somewhere the log's writer cannot change:
        an event log, another machine, a message. Test-CCFLogChain -ExpectedLastHash with those objects then finds
        lines deleted from the end, which the chain alone cannot show.
        A failure in the script block never stops logging: it is counted, and Test-CCFHealth reports it.
        With -EventLogSource, each head is written to the Windows Application log (Get-CCFChainAnchor reads them back).
        Any program can write events with a source name, so a forged anchor can raise a false alarm, but cannot hide a
        deleted line. Without -ScriptBlock or -EventLogSource, removes the registered one.

    .PARAMETER ScriptBlock
        The script block. It receives the anchor object as its only argument.

    .PARAMETER EventLogSource
        Write each head to the Windows Application log with this source name. The source does not need to be
        registered; registering it (New-EventLog, as administrator) lets the Event Viewer show the text.

    .PARAMETER EventId
        Event ID for the anchors written with -EventLogSource. Defaults to 1100.

    .PARAMETER MinimumSeconds
        Run it at most once in this many seconds for each log (the default, 0, runs it for every line). The heads
        skipped are not lost: the next one covers them, but lines deleted in between cannot be told apart.

    .EXAMPLE
        Register-CCFChainAnchor -ScriptBlock { param($a) Write-EventLog -LogName Application -Source MyApp -EventId 1000 -Message "$($a.Category) $($a.Hash)" }

        Keeps every head of the chained logs in the Application event log, with your own code.

    .EXAMPLE
        Register-CCFChainAnchor -EventLogSource 'MyApp'

        The same, written by ArgosCCF; read them back with Get-CCFChainAnchor -EventLogSource 'MyApp'.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Registers a callback in memory only.')]
    [CmdletBinding(DefaultParameterSetName = 'ScriptBlock')]
    param(
        [Parameter(ParameterSetName = 'ScriptBlock', Position = 0)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $true, ParameterSetName = 'EventLog')]
        [ValidatePattern('^[A-Za-z0-9 ._-]{1,64}$')]
        [string]$EventLogSource,

        [Parameter(ParameterSetName = 'EventLog')]
        [ValidateRange(1, 65535)]
        [int]$EventId = 1100,

        [ValidateRange(0, 86400)][int]$MinimumSeconds = 0
    )
    if ($PSCmdlet.ParameterSetName -eq 'EventLog') {
        if ($IsLinux -or $IsMacOS) { throw 'Anchors in the event log need Windows.' }
        # Kept in the module, not in a closure: a closure would not see the module's own commands.
        $script:CCFAnchorEventLog = @{ Source = $EventLogSource; EventId = $EventId }
        $ScriptBlock = {
            param($Anchor)
            $target = $script:CCFAnchorEventLog
            if (-not (Write-CCFEventLogEntry -Source $target.Source -EventId $target.EventId -Message (ConvertTo-CCFAnchorMessage -Anchor $Anchor))) { throw "The event log did not accept the anchor of $($Anchor.Path)." }
        }
    }
    $script:CCFChainAnchor = $ScriptBlock
    $script:CCFChainAnchorSeconds = $MinimumSeconds
    $script:CCFChainAnchorLast = @{}
}

# Anchors in the event log: "ArgosCCF anchor v1 Category=<c> ChainId=<id or -> Hash=<hex> File=<name>".
$script:CCFAnchorMessageRegex = [regex]'^ArgosCCF anchor v1 Category=(?<c>[A-Za-z0-9._-]+) ChainId=(?<i>[A-Za-z0-9._-]+) Hash=(?<h>[0-9a-f]{64}) File=(?<f>[A-Za-z0-9._-]+)$'

function ConvertTo-CCFAnchorMessage {
    <#
    .SYNOPSIS
        Text of an anchor written to the event log.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Anchor)
    $id = if ($Anchor.ChainId) { $Anchor.ChainId } else { '-' }
    return "ArgosCCF anchor v1 Category=$($Anchor.Category) ChainId=$id Hash=$($Anchor.Hash) File=$([System.IO.Path]::GetFileName($Anchor.Path))"
}

function ConvertFrom-CCFAnchorMessage {
    <#
    .SYNOPSIS
        The anchor in an event log message, or $null when the message is not one.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([AllowEmptyString()][string]$Message, [datetime]$Time)
    $m = $script:CCFAnchorMessageRegex.Match("$Message".Trim())
    if (-not $m.Success) { return $null }
    $id = if ($m.Groups['i'].Value -eq '-') { '' } else { $m.Groups['i'].Value }
    return [pscustomobject]@{ File = $m.Groups['f'].Value; Category = $m.Groups['c'].Value; Hash = $m.Groups['h'].Value; ChainId = $id; Time = $Time.ToUniversalTime() }
}

$script:CCFEventLogType = $null

function Write-CCFEventLogEntry {
    <#
    .SYNOPSIS
        Writes an information event to the Application log with a source name that may not be registered.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([string]$Source, [int]$EventId, [string]$Message)
    if ($null -eq $script:CCFEventLogType) {
        $script:CCFEventLogType = Add-Type -PassThru -Namespace 'ArgosCCF' -Name 'EventLogApi' -MemberDefinition @'
[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern IntPtr RegisterEventSourceW(string server, string source);
[DllImport("advapi32.dll", SetLastError = true)] public static extern bool DeregisterEventSource(IntPtr handle);
[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern bool ReportEventW(IntPtr handle, ushort type, ushort category, uint eventId, IntPtr sid, ushort count, uint size, string[] strings, IntPtr data);
'@
    }
    $handle = $script:CCFEventLogType::RegisterEventSourceW($null, $Source)
    if ($handle -eq [IntPtr]::Zero) { return $false }
    try { return [bool]$script:CCFEventLogType::ReportEventW($handle, 4, 0, [uint32]$EventId, [IntPtr]::Zero, 1, 0, [string[]]@($Message), [IntPtr]::Zero) }
    finally { $null = $script:CCFEventLogType::DeregisterEventSource($handle) }
}

function Get-CCFChainAnchor {
    <#
    .SYNOPSIS
        Reads the chain anchors that Register-CCFChainAnchor -EventLogSource wrote to the Windows Application log.

    .DESCRIPTION
        Returns one object per anchor, oldest first, with File, Category, Hash, ChainId and Time (UTC). Pass them to
        Test-CCFLogChain -ExpectedLastHash: with their time, anchors of copies that rotation or Remove-CCFOldLog deleted
        are not required. Filter by -Category, -ChainId and -File so the anchors of one log are checked against it.
        Events with the same source and ID that are not anchors are ignored.

    .PARAMETER EventLogSource
        The source name passed to Register-CCFChainAnchor.

    .PARAMETER EventId
        The event ID passed to Register-CCFChainAnchor. Defaults to 1100.

    .PARAMETER Category
        Only anchors of this log category, for example Audit.

    .PARAMETER ChainId
        Only anchors with this chain identifier (Initialize-CCFLogger -ChainId).

    .PARAMETER File
        Only anchors of this log file name, for example CCF_Audit.log.

    .PARAMETER MaxEvents
        The most recent events to read. Defaults to 5000.

    .EXAMPLE
        $anchors = Get-CCFChainAnchor -EventLogSource 'MyApp' -Category Audit
        Test-CCFLogChain -Path $auditLog -IncludeRotated -ExpectedLastHash $anchors

        Checks the audit log and that no anchored line is missing.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleCommands', '', Justification = 'Windows only: it throws on other systems before Get-WinEvent.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9 ._-]{1,64}$')]
        [string]$EventLogSource,
        [ValidateRange(1, 65535)][int]$EventId = 1100,
        [string]$Category,
        [string]$ChainId,
        [string]$File,
        [ValidateRange(1, 1000000)][int]$MaxEvents = 5000
    )
    if ($IsLinux -or $IsMacOS) { throw 'Anchors in the event log need Windows.' }
    # XPath by provider name works whether or not the source is registered.
    $xpath = "*[System[Provider[@Name='$EventLogSource'] and EventID=$EventId]]"
    $events = @()
    try { $events = @(Get-WinEvent -LogName 'Application' -FilterXPath $xpath -MaxEvents $MaxEvents -ErrorAction Stop) }
    catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw } }
    $anchors = foreach ($entry in $events) {
        $message = if ($entry.Properties.Count) { "$($entry.Properties[0].Value)" } else { "$($entry.Message)" }
        $a = ConvertFrom-CCFAnchorMessage -Message $message -Time $entry.TimeCreated
        if ($null -eq $a) { continue }
        if ($Category -and $a.Category -ne $Category) { continue }
        if ($PSBoundParameters.ContainsKey('ChainId') -and $a.ChainId -ne $ChainId) { continue }
        if ($File -and $a.File -ne $File) { continue }
        $a
    }
    $anchors | Sort-Object Time
}

function Invoke-CCFChainAnchor {
    <#
    .SYNOPSIS
        Passes a new chain head to the script block of Register-CCFChainAnchor.
    #>
    [CmdletBinding()]
    param([string]$Path, [string]$Category, [string]$Hash)
    if ($null -eq $script:CCFChainAnchor -or -not $Hash) { return }
    $now = [DateTime]::UtcNow
    $last = $script:CCFChainAnchorLast[$Path]
    if ($script:CCFChainAnchorSeconds -gt 0 -and $null -ne $last -and ($now - $last).TotalSeconds -lt $script:CCFChainAnchorSeconds) { return }
    try {
        $anchor = [pscustomobject]@{ Path = $Path; Category = $Category; Hash = $Hash; ChainId = $script:CCFChainId; Time = $now }
        $null = Invoke-Command -ScriptBlock $script:CCFChainAnchor -ArgumentList $anchor -ErrorAction Stop
        $script:CCFChainAnchorLast[$Path] = $now
    }
    catch {
        $script:CCFChainAnchorFailures++
        Write-Verbose "The chain anchor failed: $($_.Exception.Message)"
    }
}

function Test-CCFLogChain {
    <#
    .SYNOPSIS
        Checks that nobody has changed, inserted or deleted lines of a log written with Initialize-CCFLogger -Chain.

    .DESCRIPTION
        Recomputes the hash of every chained line from the one before. Returns Path, Entries (chained lines),
        Valid, BrokenAt (the first line number that does not match, or $null), Reason, LastHash and ChainId (the
        identifier of the last line), ArchivedUntil, MissingHashes and ExternalHashes. Lines written
        before the chain was enabled are skipped; an unchained line after a chained one breaks the chain.
        With -IncludeRotated the rotated copies (.N down to .1) are checked first and the chain must run across
        them from the start; otherwise the first chained line of the file is taken as given, because the line
        before it is in a rotated copy. When rotation deleted the oldest copy, the copy left starts from the hash
        recorded in its first line, and ArchivedUntil is the time of the last line deleted.
        The chain only proves something together with hashes kept where the log's writer cannot change them: whoever
        can write the file can also rewrite it and compute new hashes. ExternalHashes is how many were checked;
        with 0, Valid only means the file is consistent. Deleting the last lines is not visible either: compare LastHash with a
        copy kept elsewhere (-ExpectedLastHash).

    .PARAMETER Path
        The log file, for example the path of CCF_Audit.log.

    .PARAMETER IncludeRotated
        Also check the rotated copies and the link between them.

    .PARAMETER ExpectedLastHash
        Last hashes saved earlier (Get-CCFLogChainHead), one or several: strings, or objects with Hash and Time (when the
        hash was saved). A hash saved before the last line of a copy that rotation deleted is not required any more.
        With plain strings, every hash must still be in the log. If the chain no longer contains any of
        them, lines were deleted or the log was rewritten. With hashes saved over time, a forged later copy
        cannot hide that an earlier one is gone.

    .PARAMETER ChainId
        The identifier this log must carry (Initialize-CCFLogger -ChainId). From the first line that has one,
        every line must have this one: a line written by another program, or by another copy of the same
        program, breaks the chain. Keep the identifier where the log's writer cannot change it, and pass only
        the saved hashes that belong to it: an identifier read from the log itself proves nothing.

    .EXAMPLE
        Test-CCFLogChain -Path (Join-Path (Get-CCFPath -Target Logs) 'CCF_Audit.log') -IncludeRotated

        Checks the whole audit history.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$IncludeRotated,
        [object[]]$ExpectedLastHash,
        [ValidatePattern('^[A-Za-z0-9._-]{1,64}$')]
        [string]$ChainId
    )
    $files = @()
    if ($IncludeRotated) {
        for ($i = 100; $i -ge 1; $i--) { if ([System.IO.File]::Exists("$Path.$i")) { $files += "$Path.$i" } }
    }
    if ([System.IO.File]::Exists($Path)) { $files += $Path }
    $result = [ordered]@{ Path = $Path; Entries = 0; Valid = $true; BrokenAt = $null; Reason = ''; LastHash = $null; ChainId = ''; ArchivedUntil = $null; MissingHashes = @(); ExternalHashes = 0 }
    # Copies deleted by rotation: the oldest copy left may start from the last hash of one of them.
    $starts = @{}
    foreach ($file in $files) {
        foreach ($m in $script:CCFArchiveRegex.Matches([System.IO.File]::ReadAllText($file, [System.Text.Encoding]::UTF8))) {
            $starts[$m.Groups['hash'].Value] = $true
            $until = [datetime]::MinValue
            if ([datetime]::TryParse($m.Groups['time'].Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$until)) {
                if ($null -eq $result.ArchivedUntil -or $until -gt $result.ArchivedUntil) { $result.ArchivedUntil = $until }
            }
        }
    }
    $previous = if ($IncludeRotated) { $script:CCFChainGenesis } else { $null }
    $seen = @{}
    foreach ($file in $files) {
        $number = 0
        foreach ($line in [System.IO.File]::ReadAllLines($file, [System.Text.Encoding]::UTF8)) {
            $number++
            if ($line -eq '') { continue }
            $part = Split-CCFChainLine -Line $line
            if (-not $part.Hash) {
                if ($null -ne $result.LastHash) {
                    $result.Valid = $false; $result.BrokenAt = "${file}:$number"; $result.Reason = 'A line without a chain hash follows chained lines: it was added or changed.'
                    return [pscustomobject]$result
                }
                continue
            }
            $first = $IncludeRotated -and $result.Entries -eq 0 -and $null -eq $result.LastHash
            $fromArchive = $first -and @($starts.Keys | Where-Object { (Get-CCFChainHash -Previous $_ -Line $part.Text) -eq $part.Hash }).Count
            if (-not $fromArchive -and $null -ne $previous -and (Get-CCFChainHash -Previous $previous -Line $part.Text) -ne $part.Hash) {
                $result.Valid = $false; $result.BrokenAt = "${file}:$number"; $result.Reason = 'The hash does not match the line and the one before it: this line, or one before it, was changed, inserted or deleted.'
                return [pscustomobject]$result
            }
            $lineId = Get-CCFChainLineId -Text $part.Text
            if ($ChainId -and $lineId -ne $ChainId -and ($lineId -or $result.ChainId)) {
                $result.Valid = $false; $result.BrokenAt = "${file}:$number"; $result.Reason = 'The line does not carry the expected identifier: it was written by another program or another copy.'
                return [pscustomobject]$result
            }
            $result.ChainId = $lineId
            $previous = $part.Hash
            $seen[$part.Hash] = $true
            $result.LastHash = $part.Hash
            $result.Entries++
        }
    }
    $missing = @(foreach ($expected in @($ExpectedLastHash | Where-Object { $_ })) {
            $hash = if ($expected -is [string]) { $expected } else { "$($expected.Hash)" }
            # The last hash of a deleted copy is recorded in its archive line: it was there.
            if ($seen.ContainsKey($hash) -or $starts.ContainsKey($hash)) { continue }
            # Saved before the end of a copy that rotation deleted: it went with that copy.
            # Line times have milliseconds: a hash saved within the same millisecond is compared at that precision.
            if ($expected -isnot [string] -and $null -ne $expected.Time -and $null -ne $result.ArchivedUntil) {
                $savedAt = ([datetime]$expected.Time).ToUniversalTime()
                if ($savedAt.AddTicks(-($savedAt.Ticks % [timespan]::TicksPerMillisecond)) -le $result.ArchivedUntil) { continue }
            }
            $hash
        })
    $result.MissingHashes = $missing
    $result.ExternalHashes = @($ExpectedLastHash | Where-Object { $_ }).Count
    if ($ChainId -and $result.Entries -gt 0 -and -not $result.ChainId) {
        $result.Valid = $false; $result.Reason = 'No line carries the expected identifier.'
    }
    if ($missing.Count) {
        $result.Valid = $false; $result.Reason = 'The saved last hash is no longer in the log: lines were deleted or the log was rewritten.'
    }
    return [pscustomobject]$result
}

function Get-CCFLogChainHead {
    <#
    .SYNOPSIS
        The last chain hash of a log, to keep where the log's writer cannot change it.

    .DESCRIPTION
        Returns the hash of the last chained line (of the newest rotated copy when the log was just rotated),
        or $null when the log has no chained lines. Keep it somewhere the program that writes the log cannot
        change: another machine, an event log, a message. Test-CCFLogChain -ExpectedLastHash then shows whether
        lines were deleted from the end afterwards, which the chain alone cannot show.

    .PARAMETER Path
        The log file.

    .PARAMETER AsObject
        Returns an object with Path, Hash and ChainId instead of the hash, to save whose log the hash belongs to.

    .EXAMPLE
        $head = Get-CCFLogChainHead -Path $auditLog
        Test-CCFLogChain -Path $auditLog -ExpectedLastHash $head

        Saves the head now and later checks that no line was removed since.
    #>
    [CmdletBinding()]
    [OutputType([string], [pscustomobject])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$AsObject
    )
    $line = [ref]''
    $hash = Get-CCFLastChainHash -Path $Path -LineText $line
    if ($hash -eq $script:CCFChainGenesis) { return $null }
    if ($AsObject) { return [pscustomobject]@{ Path = $Path; Hash = $hash; ChainId = (Get-CCFChainLineId -Text $line.Value) } }
    return $hash
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
    foreach ($name in 'Get-CCFFileMutexName', 'Get-CCFFileMutex', 'Invoke-CCFLogRotation', 'Add-CCFLogText') {
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
        Checks that the Logs folder is writable, and that the chain anchor and the background writer have not failed.

    .DESCRIPTION
        Returns an object with Timestamp, Status ("OK" or "DEGRADED") and Checks: one for the
        Logs folder, one for the chain anchor when one is registered (no failures) and, with background writing,
        one for the writer (running, with no failed writes).
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

    $logsWritable = Test-CCFWritableDirectory -Path (Get-CCFPath -Target 'Logs')
    $report.Checks += @{ Target = 'LogsWritable'; Pass = $logsWritable }
    if (-not $logsWritable) { $report.Status = 'DEGRADED' }

    if ($null -ne $script:CCFChainAnchor) {
        $report.Checks += @{ Target = 'ChainAnchor'; Pass = ($script:CCFChainAnchorFailures -eq 0); Failures = $script:CCFChainAnchorFailures }
        if ($script:CCFChainAnchorFailures -gt 0) { $report.Status = 'DEGRADED' }
    }

    $writer = Get-CCFLogWriter
    if ($writer.Mode -eq 'Background') {
        $writerOk = $writer.Running -and $writer.Failed -eq 0
        $report.Checks += @{ Target = 'LogWriter'; Pass = $writerOk }
        if (-not $writerOk) { $report.Status = 'DEGRADED' }
    }

    return [PSCustomObject]$report
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

    .PARAMETER Chain
        Categories whose log files are tamper-evident, for example 'Audit' and 'Security': every line ends
        with a hash of itself and of the line before, so Test-CCFLogChain finds a line that was changed,
        inserted or deleted. Use the category name, or 'System' for the session file. These entries are
        always written directly, also with -Background.
    .PARAMETER ChainId
        Identifier of who writes the chain (letters, digits, '.', '-' and '_'), added to every chained line inside
        what is hashed. With it, Test-CCFLogChain -ChainId tells lines of another program or another copy apart.

    .PARAMETER Strict
        Entries of the chained categories, and Security and Audit records, that cannot be written throw an error
        instead of a warning, so a script can stop before doing something it could not record.

    .EXAMPLE
        Initialize-CCFLogger -Chain Audit, Security
        Audit and Security records can be checked later with Test-CCFLogChain.
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

        [switch]$Background,
        [ValidateScript({ foreach ($c in $_) { if (-not (Test-CCFLogName -Name $c)) { throw "Chain categories must contain only letters, digits, '.', '-' and '_': $c" } }; $true })]
        [string[]]$Chain = @(),

        [ValidatePattern('^[A-Za-z0-9._-]{1,64}$')]
        [string]$ChainId,

        [switch]$Strict
    )

    $script:CCFChainCategories = @($Chain)
    $script:CCFStrict = [bool]$Strict
    $script:CCFChainId = "$ChainId"
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

    .PARAMETER Strict
        Throw an error when the entry cannot be written to its file, instead of a warning. Initialize-CCFLogger
        -Strict does this for the chained categories and for Security and Audit records.

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

        [switch]$NoBuffer,

        [switch]$Strict
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
        # Chained categories are written directly: the chain needs the line the file ends with.
        $chained = @($script:CCFChainCategories) -contains $Category
        $strictWrite = $Strict -or ($script:CCFStrict -and ($chained -or $Category -eq 'Security' -or $Category -eq 'Audit'))
        $queued = $false
        if ($null -ne $script:CCFWriter -and -not $chained -and -not $strictWrite) {
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
                $head = Add-CCFLogText -Path $targetFile -Text $text -MaxMB $script:MaxLogSizeMB -MaxRolling $script:MaxLogRolling -Chain:$chained -ChainId $script:CCFChainId
                if ($chained) { Invoke-CCFChainAnchor -Path $targetFile -Category $Category -Hash $head }
            }
            catch {
                $message = "Could not write to ${targetFile}: $($_.Exception.Message)"
                if ($strictWrite) { throw "ArgosCCF: a $Category $Level entry was not saved. $message" }
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
        Shortcut for Write-CCFLog -Level INFO.
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
        Shortcut for Write-CCFLog -Level SUCCESS, shown in green on the console. Message and Data can be passed by position.

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
        Shortcut for Write-CCFLog -Level WARN, shown in yellow on the console. Message and Data can be passed by position.

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
        does not write to the error stream or stop the script. Message and Data can be passed by position.

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
        failures that need immediate attention. Message and Data can be passed by position.

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
        Set-CCFLogLevel -Level DEBUG.
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
        script in the log.

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
        script detects or blocks something suspicious.

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
    .PARAMETER Strict
        Throw an error if the record cannot be written, instead of a warning.

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
        [hashtable]$Metadata = @{},
        [switch]$Strict
    )

    $data = @{ Type = $Type; Source = $Source; Payload = $Payload; Metadata = $Metadata }
    Write-CCFLog -Message "[SECURITY] $Type from $Source" -Level $Severity -Category 'Security' -Data $data -Strict:$Strict
}

function Write-CCFAuditRecord {
    <#
    .SYNOPSIS
        Records who did what, on which resource, in CCF_Audit.log.

    .DESCRIPTION
        Logs "[AUDIT] <User> <Action> <Resource>" at INFO level in the Audit category, with the
        outcome and metadata as data. Use it for actions that must be traceable, such as
        deletions or configuration changes.

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
    .PARAMETER Strict
        Throw an error if the record cannot be written, instead of a warning.

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
        [hashtable]$Metadata = @{},
        [switch]$Strict
    )

    $data = @{ Action = $Action; User = $User; Resource = $Resource; Outcome = $Outcome; Metadata = $Metadata }
    Write-CCFLog -Message ("[AUDIT] $User $Action $Resource".Trim()) -Level 'INFO' -Category 'Audit' -Data $data -Strict:$Strict
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
        A chained log (Initialize-CCFLogger -Chain) keeps its current file, and loses only its oldest rotated copies,
        oldest first: the deletion is recorded in the current file, so Test-CCFLogChain still checks what is left.

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
    $candidates = @(Get-ChildItem -LiteralPath $logDir -File |
            Where-Object { $_.Name -match '\.log(\.\d+)?$' -and $_.LastWriteTime -lt $cutoff })
    # A chained log loses only its oldest rotated copies, oldest first, and never the current file: deleting a copy in
    # the middle, or the end of the chain, would look like tampering. The deletion is recorded in the current file.
    $oldFiles = @(); $archives = [ordered]@{}
    foreach ($group in @($candidates | Group-Object { $_.Name -replace '\.\d+$', '' })) {
        $base = Join-Path $logDir $group.Name
        $all = @(Get-ChildItem -LiteralPath $logDir -File | Where-Object { $_.Name -eq $group.Name -or $_.Name -match ('^' + [regex]::Escape($group.Name) + '\.\d+$') })
        $chained = @($all | Where-Object { (Get-CCFLastChainHash -Path $_.FullName) -ne $script:CCFChainGenesis }).Count -gt 0
        if (-not $chained) { $oldFiles += $group.Group; continue }
        $old = @{}; foreach ($f in $group.Group) { $old[$f.Name] = $f }
        $numbers = @($all | Where-Object { $_.Name -match '\.(\d+)$' } | ForEach-Object { [int]($_.Name -replace '^.*\.', '') } | Sort-Object -Descending)
        foreach ($n in $numbers) {
            $file = $old["$($group.Name).$n"]
            if (-not $file) { break }
            $oldFiles += $file
            if (-not $archives.Contains($base)) { $archives[$base] = [System.Collections.Generic.List[string]]::new() }
            $line = Get-CCFArchiveLine -Path $file.FullName
            if ($line) { $archives[$base].Add($line) }
        }
    }
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

    $removed = @(foreach ($file in $oldFiles) {
            if ($PSCmdlet.ShouldProcess($file.FullName, 'Delete')) {
                Remove-Item -LiteralPath $file.FullName -Force
                $file.FullName
            }
        })
    # Record the deleted copies of each chained log, so Test-CCFLogChain -IncludeRotated starts after them.
    foreach ($base in $archives.Keys) {
        $lines = @($archives[$base] | Where-Object { $removed -contains (Join-Path $logDir (($_ -replace '^.*\[CHAIN\] Archived ', '') -replace ':.*$', '')) })
        if ($lines.Count) { $null = Add-CCFLogText -Path $base -Text (($lines -join [Environment]::NewLine) + [Environment]::NewLine) -MaxMB $script:MaxLogSizeMB -MaxRolling $script:MaxLogRolling -Chain -ChainId $script:CCFChainId }
    }
    return [string[]]@($removed | ForEach-Object { Split-Path $_ -Leaf })
}

# Names from earlier versions, kept so existing scripts keep working.
