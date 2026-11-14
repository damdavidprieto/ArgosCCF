# ArgosCCF - configuration, logging, plugins and parallel execution for PowerShell scripts.
#
# Resolves the module's folders, then dot-sources the Core files into this module's scope.
# License: MIT

$script:ArgosCCFRoot = (Get-Item $PSScriptRoot).FullName
$script:PathCache = [System.Collections.Concurrent.ConcurrentDictionary[string, string]]::new()

function Test-CCFWritableDirectory {
    <#
    .SYNOPSIS
        True when the folder exists (or can be created) and a file can be written in it.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null }
        $probe = Join-Path $Path '.ccf_write_test'
        'test' | Out-File -LiteralPath $probe -ErrorAction Stop
        Remove-Item -LiteralPath $probe -ErrorAction SilentlyContinue
        return $true
    }
    catch {
        return $false
    }
}

function Test-CCFPathInside {
    <#
    .SYNOPSIS
        True when Path, after resolving "..", is BasePath itself or a folder inside it.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([string]$Path, [string]$BasePath)

    try {
        $full = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
        $base = [System.IO.Path]::GetFullPath($BasePath).TrimEnd('\', '/')
    }
    catch { return $false }

    $comparison = if ($IsLinux -or $IsMacOS) { [StringComparison]::Ordinal } else { [StringComparison]::OrdinalIgnoreCase }
    return ($full.Equals($base, $comparison) -or $full.StartsWith($base + [System.IO.Path]::DirectorySeparatorChar, $comparison))
}

function Initialize-CCFEnvironment {
    <#
    .SYNOPSIS
        Finds the module folders and chooses a writable folder for the logs.

    .DESCRIPTION
        Runs automatically when the module is imported. It creates the Configs and Plugins
        folders if they are missing and chooses the Logs folder: next to the module when it
        is writable, otherwise (for example when installed for all users under Program Files)
        ArgosCCF\Logs under %LOCALAPPDATA%, $XDG_DATA_HOME or ~/.local/share.
        If the module folder has no Core folder (for example when only the script files were
        copied), the folder in $env:ARGOS_CCF_ROOT is used as the root instead.

    .EXAMPLE
        Initialize-CCFEnvironment; Get-CCFPath -Target Logs

        Chooses the folders again and shows where the logs are written.
    #>
    [CmdletBinding()]
    param()

    $script:ArgosCCFRoot = (Get-Item $PSScriptRoot).FullName
    if (-not (Test-Path -LiteralPath (Join-Path $script:ArgosCCFRoot 'Core')) -and $env:ARGOS_CCF_ROOT -and (Test-Path -LiteralPath $env:ARGOS_CCF_ROOT -PathType Container)) {
        $script:ArgosCCFRoot = (Get-Item -LiteralPath $env:ARGOS_CCF_ROOT).FullName
    }
    $script:PathCache.Clear()

    foreach ($p in 'Configs', 'Plugins') {
        $path = Join-Path $script:ArgosCCFRoot $p
        if (-not (Test-Path -LiteralPath $path)) {
            try { New-Item -ItemType Directory -Path $path -Force -ErrorAction Stop | Out-Null }
            catch { Write-Verbose "Could not create ${path}: $($_.Exception.Message)" }
        }
    }

    $script:LogsPath = Join-Path $script:ArgosCCFRoot 'Logs'
    if (-not (Test-CCFWritableDirectory -Path $script:LogsPath)) {
        $userData = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA }
        elseif ($env:XDG_DATA_HOME) { $env:XDG_DATA_HOME }
        else { Join-Path $HOME '.local/share' }
        $script:LogsPath = Join-Path (Join-Path $userData 'ArgosCCF') 'Logs'
        if (-not (Test-CCFWritableDirectory -Path $script:LogsPath)) {
            Write-Warning 'ArgosCCF: no writable folder for logs was found; log entries will only be shown on the console.'
        }
    }
}

function Get-CCFPath {
    <#
    .SYNOPSIS
        Returns the full path of one of the ArgosCCF folders.

    .DESCRIPTION
        Returns the folder used for Root, Core, Configs, Logs, Tests or Plugins. Results are
        cached for the session. The Logs folder can be changed with Logging.DefaultPath in the
        ccf_core configuration; the override is used only when, after resolving "..", it is
        inside the module root or inside $env:CCF_DATA_PATH. Otherwise it is ignored and a
        warning is logged, so a configuration file cannot send logs to an arbitrary folder.

    .PARAMETER Target
        The folder to return: Root, Core, Configs, Logs, Tests or Plugins.

    .EXAMPLE
        Get-CCFPath -Target Logs

        Returns the folder where log files are written.

    .EXAMPLE
        Get-ChildItem (Get-CCFPath -Target Plugins) -Recurse -Filter *.ps1

        Lists the plugin scripts.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Root', 'Core', 'Configs', 'Logs', 'Tests', 'Plugins')]
        [string]$Target
    )

    $memoized = $null
    if ($script:PathCache.TryGetValue($Target, [ref]$memoized)) { return $memoized }

    if ($Target -eq 'Logs' -and (Get-Command -Name 'Get-CCFConfig' -ErrorAction SilentlyContinue)) {
        $override = $null
        try { $override = (Get-CCFConfig -ConfigName 'ccf_core').Logging.DefaultPath } catch { $override = $null }

        if ($override) {
            $targetPath = if ([System.IO.Path]::IsPathRooted($override)) { $override } else { Join-Path $script:ArgosCCFRoot $override }
            $allowedBase = if ($env:CCF_DATA_PATH) { $env:CCF_DATA_PATH } else { $script:ArgosCCFRoot }
            if (Test-CCFPathInside -Path $targetPath -BasePath $allowedBase) {
                $finalPath = [System.IO.Path]::GetFullPath($targetPath)
                $null = $script:PathCache.TryAdd($Target, $finalPath)
                return $finalPath
            }
            Write-CCFLogWarn "SECURITY BLOCK: Logging.DefaultPath points outside the allowed folder and was ignored: $override"
        }
    }

    $finalPath = switch ($Target) {
        'Root' { $script:ArgosCCFRoot }
        'Core' { Join-Path $script:ArgosCCFRoot 'Core' }
        'Configs' { Join-Path $script:ArgosCCFRoot 'Configs' }
        'Logs' { $script:LogsPath }
        'Tests' { Join-Path $script:ArgosCCFRoot 'Tests' }
        'Plugins' { Join-Path $script:ArgosCCFRoot 'Plugins' }
    }

    $null = $script:PathCache.TryAdd($Target, $finalPath)
    return $finalPath
}

# --- Core ---
# The Core files are dot-sourced into this module's scope, so their functions can call each
# other and are exported only through the list below (and the manifest).
$corePath = Join-Path $PSScriptRoot 'Core'
foreach ($coreFile in 'Logging.ps1', 'Configuration.ps1', 'Plugins.ps1', 'Execution.ps1') {
    . (Join-Path $corePath $coreFile)
}

Initialize-CCFEnvironment

# Keep in sync with FunctionsToExport / AliasesToExport in ArgosCCF.psd1 (tests/QA checks it).
Export-ModuleMember -Function @(
    'Get-CCFPath', 'Initialize-CCFEnvironment',
    'Set-CCFLogLevel', 'Register-CCFLogProvider', 'Register-CCFSIEMProvider', 'Initialize-CCFLogger',
    'Write-CCFLog', 'Write-CCFLogInfo', 'Write-CCFLogSuccess', 'Write-CCFLogWarn', 'Write-CCFLogError',
    'Write-CCFLogCritical', 'Write-CCFLogDebug', 'Write-CCFLogHeader',
    'Write-CCFSecurityRecord', 'Write-CCFAuditRecord', 'Write-CCFErrorRecord', 'Remove-CCFOldLog',
    'Protect-CCFSensitiveData', 'Test-CCFEntropyContent', 'Test-CCFHealth', 'Submit-CCFHeartbeat',
    'Get-CCFConfig', 'Set-CCFUserConfig', 'Merge-CCFConfig', 'Remove-CCFConfigCache', 'Test-CCFConfigSchema',
    'Get-CCFPlugin', 'Invoke-CCFPlugin', 'Confirm-CCFPluginSignature',
    'Invoke-CCFParallel'
) -Alias @(
    'Log-Info', 'Log-Success', 'Log-Warn', 'Log-Error', 'Log-Critical', 'Log-Debug', 'Log-Header',
    'Log-Attack', 'Log-Audit', 'Init-CCFLogger', 'Catch-CCFError', 'Redact-CCFSensitiveData',
    'Test-CCFHighEntropy', 'Remove-OldCCFLogs', 'Clear-CCFConfigCache', 'Test-CCFPluginSignature',
    'Get-CCFPlugins'
)
