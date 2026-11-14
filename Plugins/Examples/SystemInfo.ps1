<#
.NAME
SystemInfo

.DESCRIPTION
Returns basic information about the machine and the PowerShell session.

.VERSION
1.1.0

.AUTHOR
David Prieto
#>

# Example plugin: works on Windows, Linux and macOS and returns its data instead of printing it.
# Pass -Arguments @{ IncludeEnvironment = $true } to add the PATH entries.
param($Arguments)

Write-CCFLogInfo 'Collecting system information...'

$systemInfo = [ordered]@{
    Hostname          = [Environment]::MachineName
    User              = [Environment]::UserName
    OS                = [Environment]::OSVersion.VersionString
    Is64BitOS         = [Environment]::Is64BitOperatingSystem
    ProcessorCount    = [Environment]::ProcessorCount
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    PowerShellEdition = $PSVersionTable.PSEdition
    SessionStarted    = (Get-Process -Id $PID).StartTime
    Timestamp         = Get-Date
}

if ($Arguments.IncludeEnvironment) {
    $systemInfo.Path = $env:PATH -split [System.IO.Path]::PathSeparator
}

Write-CCFLogSuccess "System information collected for $($systemInfo.Hostname)"
return [pscustomobject]$systemInfo
