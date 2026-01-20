<#
.NAME
SystemInfo

.DESCRIPTION
Collects and returns system information

.VERSION
1.0.0

.AUTHOR
ArgosCCF Team
#>

param($Arguments)

try {
    Log-Info "Collecting system information..."
    
    # Gather system information
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
    
    $systemInfo = @{
        Hostname             = $env:COMPUTERNAME
        OS                   = $os.Caption
        OSVersion            = $os.Version
        Architecture         = $os.OSArchitecture
        TotalMemoryGB        = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
        FreeMemoryGB         = [math]::Round($os.FreePhysicalMemory / 1MB / 1024, 2)
        CPU                  = $cpu.Name
        CPUCores             = $cpu.NumberOfCores
        CPULogicalProcessors = $cpu.NumberOfLogicalProcessors
        Uptime               = (Get-Date) - $os.LastBootUpTime
        CurrentUser          = $env:USERNAME
        PowerShellVersion    = $PSVersionTable.PSVersion.ToString()
        Timestamp            = Get-Date
    }
    
    Log-Success "System information collected successfully"
    
    # Display summary
    Write-Host "`nSystem Information:" -ForegroundColor Cyan
    Write-Host "  Hostname: $($systemInfo.Hostname)" -ForegroundColor Yellow
    Write-Host "  OS: $($systemInfo.OS)" -ForegroundColor Yellow
    Write-Host "  Memory: $($systemInfo.FreeMemoryGB)GB free / $($systemInfo.TotalMemoryGB)GB total" -ForegroundColor Yellow
    Write-Host "  CPU: $($systemInfo.CPU)" -ForegroundColor Yellow
    Write-Host "  Uptime: $($systemInfo.Uptime.Days) days, $($systemInfo.Uptime.Hours) hours" -ForegroundColor Yellow
    
    return $systemInfo
}
catch {
    Log-Error "Failed to collect system information: $($_.Exception.Message)"
    Catch-CCFError -ErrorRecord $_ -Context "SystemInfoPlugin"
    return $null
}
