# ArgosCCF - secure logging for PowerShell scripts: secrets are redacted before anything is
# written. Also kept: layered configuration, plugins and parallel execution (deprecated).
#
# Resolves the module and data folders, then dot-sources the Core files into this module's scope.
# License: MIT

# Module state. Everything the module keeps between calls is in one of these five groups, instead of about
# seventy separate script variables. A function copies the group it uses into a local variable of the same name
# ($CCFLog = $script:CCFLog), so it names the module state once: the groups are created here, before the Core files.
$script:CCFPaths = @{}
$script:CCFLog = @{}
$script:CCFMutex = @{}
$script:CCFChain = @{}
$script:CCFRedact = @{}
$script:CCFPaths.Root = (Get-Item $PSScriptRoot).FullName
$script:CCFPaths.Cache = [System.Collections.Concurrent.ConcurrentDictionary[string, string]]::new()
$script:CCFPaths.LogsPathOverride = $null

function Test-CCFWritableDirectory {
    <#
    .SYNOPSIS
        True when the folder exists (or can be created) and a file can be written in it.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        # CreateDirectory does nothing when the folder exists, so callers in parallel do not collide.
        $null = [System.IO.Directory]::CreateDirectory($Path)
        # A unique probe name per call: runspaces or processes checking the same folder at the
        # same time would otherwise collide on one file and wrongly report it as read-only.
        $probe = Join-Path $Path ('.ccf_write_test_' + [guid]::NewGuid().ToString('N'))
        [System.IO.File]::WriteAllText($probe, 'test')
        Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
        return $true
    }
    catch {
        return $false
    }
}

function Get-CCFDataRoot {
    <#
    .SYNOPSIS
        The per-user folder for logs and user settings: $env:CCF_DATA_PATH, or ArgosCCF under %LOCALAPPDATA%, $XDG_DATA_HOME or ~/.local/share.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if ($env:CCF_DATA_PATH) { return [System.IO.Path]::GetFullPath($env:CCF_DATA_PATH) }
    $userData = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA }
    elseif ($env:XDG_DATA_HOME) { $env:XDG_DATA_HOME }
    else { Join-Path $HOME '.local/share' }
    return (Join-Path $userData 'ArgosCCF')
}

function Initialize-CCFEnvironment {
    <#
    .SYNOPSIS
        Finds the module folders and the per-user folder for logs and settings.

    .DESCRIPTION
        Runs automatically when the module is imported. ArgosCCF never writes into the folder it
        is installed in, so updating or removing the module keeps your logs and settings, and an
        all-users install works without administrator rights. Logs and user settings go to the
        data folder: $env:CCF_DATA_PATH when it is set, otherwise ArgosCCF under %LOCALAPPDATA%
        on Windows, or under $XDG_DATA_HOME or ~/.local/share on Linux and macOS.
        If the module folder has no Core folder (for example when only the script files were
        copied), the folder in $env:ARGOS_CCF_ROOT is used as the module root instead.
        Run it again after changing $env:CCF_DATA_PATH. It also clears the folder chosen with
        Initialize-CCFLogger -Path.

    .EXAMPLE
        $env:CCF_DATA_PATH = 'D:\AppData\Backup'; Initialize-CCFEnvironment; Get-CCFPath -Target Logs

        Moves the logs and user settings of this session to D:\AppData\Backup.
    #>
    [CmdletBinding()]
    param()

    $CCFPaths = $script:CCFPaths
    $CCFPaths.Root = (Get-Item $PSScriptRoot).FullName
    if (-not (Test-Path -LiteralPath (Join-Path $CCFPaths.Root 'Core')) -and $env:ARGOS_CCF_ROOT -and (Test-Path -LiteralPath $env:ARGOS_CCF_ROOT -PathType Container)) {
        $CCFPaths.Root = (Get-Item -LiteralPath $env:ARGOS_CCF_ROOT).FullName
    }
    $CCFPaths.Cache.Clear()
    $CCFPaths.LogsPathOverride = $null

    $CCFPaths.DataRoot = Get-CCFDataRoot
    $CCFPaths.LogsPath = Join-Path $CCFPaths.DataRoot 'Logs'
    if (-not (Test-CCFWritableDirectory -Path $CCFPaths.LogsPath)) {
        Write-Warning "ArgosCCF: the logs folder $($CCFPaths.LogsPath) cannot be written; log entries will only be shown on the console. Set `$env:CCF_DATA_PATH or use Initialize-CCFLogger -Path."
    }
}

function Get-CCFPath {
    <#
    .SYNOPSIS
        Returns the full path of one of the ArgosCCF folders.

    .DESCRIPTION
        Returns the folder used for Root (the module), Core, Data (the per-user folder for logs, see
        Initialize-CCFEnvironment) or Logs: the folder given to Initialize-CCFLogger -Path, or Logs inside the
        data folder. Results are cached for the session.

    .PARAMETER Target
        The folder to return: Root, Core, Logs or Data.

    .EXAMPLE
        Get-CCFPath -Target Logs

        Returns the folder where log files are written.

    .EXAMPLE
        Get-ChildItem (Get-CCFPath -Target Logs) -Filter *.log

        Lists the log files.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Root', 'Core', 'Logs', 'Data')]
        [string]$Target
    )

    $CCFPaths = $script:CCFPaths
    if ($Target -eq 'Logs' -and $CCFPaths.LogsPathOverride) { return $CCFPaths.LogsPathOverride }

    $memoized = $null
    if ($CCFPaths.Cache.TryGetValue($Target, [ref]$memoized)) { return $memoized }

    $finalPath = switch ($Target) {
        'Root' { $CCFPaths.Root }
        'Core' { Join-Path $CCFPaths.Root 'Core' }
        'Logs' { $CCFPaths.LogsPath }
        'Data' { $CCFPaths.DataRoot }
    }

    $null = $CCFPaths.Cache.TryAdd($Target, $finalPath)
    return $finalPath
}

# --- Core ---
# The Core files are dot-sourced into this module's scope, so their functions can call each
# other and are exported only through the list below (and the manifest).
$corePath = Join-Path $PSScriptRoot 'Core'
foreach ($coreFile in 'Redaction.ps1', 'Logging.ps1') { . (Join-Path $corePath $coreFile) }

Initialize-CCFEnvironment

# Write out queued log entries when the module is removed or imported again.
$ExecutionContext.SessionState.Module.OnRemove = { Stop-CCFLogWriter -TimeoutSeconds 10; Close-CCFFileMutex }

# Keep in sync with FunctionsToExport / AliasesToExport in ArgosCCF.psd1 (tests/QA checks it).
Export-ModuleMember -Function @(
    'Get-CCFPath', 'Initialize-CCFEnvironment',
    'Set-CCFLogLevel', 'Register-CCFLogProvider', 'Register-CCFSIEMProvider', 'Initialize-CCFLogger',
    'Write-CCFLog', 'Write-CCFLogInfo', 'Write-CCFLogSuccess', 'Write-CCFLogWarn', 'Write-CCFLogError',
    'Write-CCFLogCritical', 'Write-CCFLogDebug', 'Write-CCFLogHeader',
    'Write-CCFSecurityRecord', 'Write-CCFAuditRecord', 'Write-CCFErrorRecord', 'Remove-CCFOldLog',
    'Test-CCFLogChain', 'Get-CCFLogChainHead', 'Register-CCFChainAnchor', 'Get-CCFChainAnchor', 'New-CCFChainKey', 'Export-CCFEvidence',
    'Save-CCFChainAnchor', 'Write-CCFAnchor', 'Get-CCFAnchor', 'Set-CCFAnchorStore',
    'Get-CCFFolderHash', 'Add-CCFFolderHash', 'Test-CCFFolderChain', 'Set-CCFRedactionOption',
    'Get-CCFLogWriter', 'Wait-CCFLogWriter', 'Stop-CCFLogWriter',
    'Protect-CCFSensitiveData', 'Test-CCFEntropyContent', 'Test-CCFHealth',
    'Register-CCFSecret', 'Unregister-CCFSecret', 'Register-CCFRedactionPattern', 'Unregister-CCFRedactionPattern',
    'Get-CCFRedactionPattern', 'Protect-CCFLogFile'
)
