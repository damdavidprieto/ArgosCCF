<#
    .SYNOPSIS
    CCF Logging Engine - Professional & Decoupled
    
    .DESCRIPTION
    Motor de logging para CCF. Permite registrar mensajes en consola y archivo.
    Implementa un sistema de proveedores para que la UI se conecte dinámicamente.
#>

$script:LogProvider = $null
$script:SIEMProvider = $null # Hook para exportación SIEM (Samael)
$script:CurrentLogFile = $null
$script:LogBuffer = New-Object System.Collections.Generic.List[PSCustomObject]
$script:MaxLogSizeMB = 10
$script:LogLevels = @{ "DEBUG" = 0; "INFO" = 1; "WARN" = 2; "SUCCESS" = 2; "ERROR" = 3; "CRITICAL" = 4 }
$script:CurrentLogLevel = 1 # Por defecto INFO
$script:JsonOutput = $false

# --- Configuración de Nivel ---
function Set-CCFLogLevel {
    param([ValidateSet("DEBUG", "INFO", "WARN", "ERROR", "CRITICAL")]$Level)
    $script:CurrentLogLevel = $script:LogLevels[$Level]
}

# --- Registro de Proveedores ---
function Register-CCFLogProvider {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ProviderScript
    )
    $script:LogProvider = $ProviderScript
    Write-CCFLog "Log Provider (Console/UI) registrado correctamente." -Level "SUCCESS"
}

function Register-CCFSIEMProvider {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ProviderScript
    )
    $script:SIEMProvider = $ProviderScript
    Write-CCFLog "SIEM Provider (Samael/Export) registrado correctamente." -Level "SUCCESS"
}

# --- Motor de Sanitización (Análisis de Entropía) ---
function Test-CCFEntropyContent {
    param([string]$String)
    if ($null -eq $String -or $String.Length -lt 20 -or $String -match "\s") { return $false }
    if ($String -match "[\\/:]") { return $false }

    $hasUpper = $String -match "[A-Z]"
    $hasLower = $String -match "[a-z]"
    $hasNum = $String -match "[0-9]"
    $hasSpecial = $String -match "[-_+=]"
    
    $typeCount = 0
    if ($hasUpper) { $typeCount++ }
    if ($hasLower) { $typeCount++ }
    if ($hasNum) { $typeCount++ }
    if ($hasSpecial) { $typeCount++ }
    
    return ($typeCount -ge 3 -or ($typeCount -ge 2 -and $String.Length -gt 32))
}

function Get-CCFSecretsRegex {
    return "(?i)(password|passwd|pwd|token|api_key|secret|authorization|auth_token|apikey)"
}

function Invoke-CCFEntropyScan {
    param([string]$InputString)
    if ($null -eq $InputString) { return "" }
    $words = $InputString -split "\s+"
    $newWords = foreach ($word in $words) {
        $cleanWord = $word -replace "[,;.:]$", ""
        if (Test-CCFEntropyContent -String $cleanWord) {
            "[REDACTED-ENTROPY]"
        }
        else {
            $word
        }
    }
    return $newWords -join " "
}

function Protect-CCFSensitiveData {
    param(
        [Parameter(Mandatory = $true)][object]$InputData,
        [int]$Depth = 0
    )
    
    if ($Depth -gt 5 -or $null -eq $InputData) { return $InputData }
    
    $secretsRegex = Get-CCFSecretsRegex
    
    if ($InputData -is [string]) {
        if ($InputData -match "$secretsRegex\s*[:=]\s*(\S+)") {
            $InputData = $InputData -replace "$secretsRegex\s*[:=]\s*(\S+)", '$1=[REDACTED]'
        }
        
        if ($InputData.Length -lt 2000) {
            return Invoke-CCFEntropyScan -InputString $InputData
        }
        return $InputData
    }
    elseif ($InputData -is [hashtable] -or $InputData -is [PSCustomObject]) {
        if ($null -ne $InputData -and ($InputData.GetType().FullName -match "System\.Reflection|System\.Management|System\.Runtime")) {
            return $InputData.ToString()
        }

        $newData = if ($InputData -is [hashtable]) { @{} } else { [PSCustomObject]@{} }
        $props = if ($InputData -is [hashtable]) { $InputData.Keys } else { $InputData.PSObject.Properties.Name }
        
        foreach ($prop in $props) {
            if ($prop -eq "PSObject" -or $prop -eq "PSStandardMembers") { continue }
            $val = try { if ($InputData -is [hashtable]) { $InputData[$prop] } else { $InputData.$prop } } catch { $null }
            
            $isSecret = $prop -match $secretsRegex
            if ($val -is [string] -and (Test-CCFEntropyContent -String $val)) { $isSecret = $true }
            
            if ($isSecret) {
                if ($InputData -is [hashtable]) { $newData[$prop] = "[REDACTED]" } else { $newData | Add-Member -NotePropertyName $prop -NotePropertyValue "[REDACTED]" -Force }
            }
            elseif ($val -is [hashtable] -or $val -is [PSCustomObject]) {
                $redactedVal = Protect-CCFSensitiveData -InputData $val -Depth ($Depth + 1)
                if ($InputData -is [hashtable]) { $newData[$prop] = $redactedVal } else { $newData | Add-Member -NotePropertyName $prop -NotePropertyValue $redactedVal -Force }
            }
            else {
                if ($InputData -is [hashtable]) { $newData[$prop] = $val } else { $newData | Add-Member -NotePropertyName $prop -NotePropertyValue $val -Force }
            }
        }
        return $newData
    }
    return $InputData
}

# --- Salud e Integración ---
$script:LastProviderHeartbeat = $null

function Test-CCFHealth {
    [CmdletBinding()]
    param()
    
    $report = [ordered]@{
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Status    = "OK"
        Checks    = @()
    }

    $coreModules = @("Logging", "Configuration", "Execution", "Plugins")
    foreach ($mod in $coreModules) {
        $loaded = $null -ne (Get-Module -Name $mod)
        $report.Checks += @{ Target = "Module:$mod"; Pass = $loaded }
        if (-not $loaded) { $report.Status = "DEGRADED" }
    }

    return [PSCustomObject]$report
}

function Submit-CCFHeartbeat {
    [CmdletBinding()]
    param()
    $script:LastProviderHeartbeat = Get-Date
}

# --- Motor de Logging ---

function Initialize-CCFLogger {
    param(
        [string]$FileName = "CCF_Session.log",
        [int]$MaxMB = 10,
        [int]$MaxRolling = 5
    )
    
    $script:CCFSystemMeta = [ordered]@{
        Hostname = $env:COMPUTERNAME
        Version  = "1.3.0"
        Engine   = "ArgosCCF"
    }

    $logDir = Get-CCFPath -Target "Logs"
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    
    $script:CurrentLogFile = Join-Path $logDir $FileName
    $script:MaxLogSizeMB = $MaxMB
    
    if (Test-Path $script:CurrentLogFile) {
        $size = (Get-Item $script:CurrentLogFile).Length / 1MB
        if ($size -gt $script:MaxLogSizeMB) {
            for ($i = $MaxRolling - 1; $i -ge 1; $i--) {
                $old = "$($script:CurrentLogFile).$i"
                $new = "$($script:CurrentLogFile).$($i + 1)"
                if (Test-Path $old) { Move-Item -Path $old -Destination $new -Force }
            }
            Move-Item -Path $script:CurrentLogFile -Destination "$($script:CurrentLogFile).1" -Force
        }
    }
}

function Write-CCFLog {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "CRITICAL", "DEBUG")]
        [string]$Level = "INFO",
        [string]$Color = "White",
        [hashtable]$Data = @{},
        [string]$Category = "System",
        [switch]$NoBuffer
    )
    
    $msgLevel = $script:LogLevels[$Level]
    if ($msgLevel -lt $script:CurrentLogLevel) { return }

    $cleanMessage = Protect-CCFSensitiveData -InputData $Message
    $cleanData = Protect-CCFSensitiveData -InputData $Data
    $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
    $rsId = if ($null -ne [runspace]::DefaultRunspace) { [runspace]::DefaultRunspace.Id } else { 1 }
    
    $logEntry = [ordered]@{
        Timestamp = $timestamp
        Level     = $Level
        Category  = $Category
        Message   = $cleanMessage
        Data      = $cleanData
        Context   = @{ RSID = $rsId }
    }

    # 1. Consola / Provider de UI
    if ($null -ne $script:LogProvider) {
        try {
            Invoke-Command -ScriptBlock $script:LogProvider -ArgumentList @{ Entry = $logEntry; Color = $Color } -ErrorAction Stop
        }
        catch {
            Write-Host "[FALLBACK] [$Level] $cleanMessage" -ForegroundColor Yellow
        }
    }
    else {
        $fColor = switch ($Level) {
            "SUCCESS" { "Green" }
            "WARN" { "Yellow" }
            "ERROR" { "Red" }
            "CRITICAL" { "Magenta" }
            "DEBUG" { "Gray" }
            default { $Color }
        }
        Write-Host "[$timestamp] [$Level] [$Category] $cleanMessage" -ForegroundColor $fColor
    }

    # 2. SIEM Export (Samael Integration)
    if ($null -ne $script:SIEMProvider) {
        try {
            # Se envía el logEntry completo (ya sanitizado) al proveedor SIEM
            Invoke-Command -ScriptBlock $script:SIEMProvider -ArgumentList @{ Entry = $logEntry } -ErrorAction SilentlyContinue
        }
        catch {
            # Fallo silencioso en SIEM para no bloquear el hilo principal
        }
    }
    
    # Archivo
    $targetFile = $script:CurrentLogFile
    if ($Category -ne "System") {
        $logDir = Get-CCFPath -Target "Logs"
        if (-not (Test-Path $logDir)) { try { New-Item -ItemType Directory -Path $logDir -Force | Out-Null } catch {} }
        $targetFile = Join-Path $logDir "CCF_${Category}.log"
    }

    if ($null -ne $targetFile) {
        Write-Host "[DEBUG-LOG] Target: '$targetFile'" -ForegroundColor Cyan
        $outMsg = if ($script:JsonOutput) { $logEntry | ConvertTo-Json -Depth 5 -Compress } else { "[$timestamp] [$Level] [$Category] $cleanMessage" }
        try {
            $parent = Split-Path $targetFile -Parent
            if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
            $outMsg | Out-File -FilePath $targetFile -Append -Encoding UTF8 -ErrorAction Stop
        }
        catch {
            # Evitar bucle infinito de logs si falla el archivo
        }
    }
}

function Write-CCFErrorRecord {
    param([Parameter(Mandatory = $true)][System.Management.Automation.ErrorRecord]$ErrorRecord, [string]$Context = "General")
    $data = [ordered]@{ Exception = $ErrorRecord.Exception.GetType().Name; StackTrace = $ErrorRecord.ScriptStackTrace }
    Write-CCFLog -Message "[$Context] $($ErrorRecord.Exception.Message)" -Level "ERROR" -Category "Errors" -Data $data
}

function Write-CCFLogInfo ($m, $d = @{}) { Write-CCFLog $m -Level "INFO" -Data $d }
function Write-CCFLogSuccess ($m, $d = @{}) { Write-CCFLog $m -Level "SUCCESS" -Data $d }
function Write-CCFLogWarn ($m, $d = @{}) { Write-CCFLog $m -Level "WARN" -Data $d }
function Write-CCFLogError ($m, $d = @{}) { Write-CCFLog $m -Level "ERROR" -Data $d }
function Write-CCFLogCritical ($m, $d = @{}) { Write-CCFLog $m -Level "CRITICAL" -Data $d }
function Write-CCFLogDebug ($m, $d = @{}) { Write-CCFLog $m -Level "DEBUG" -Data $d }
function Write-CCFLogHeader ($m) { Write-CCFLog $m -Level "INFO" -Color "Cyan" }

# Alias para Bridge
New-Alias -Name Log-Info -Value Write-CCFLogInfo -Description "Alias para Write-CCFLogInfo"
New-Alias -Name Log-Success -Value Write-CCFLogSuccess
New-Alias -Name Log-Warn -Value Write-CCFLogWarn
New-Alias -Name Log-Error -Value Write-CCFLogError
New-Alias -Name Log-Critical -Value Write-CCFLogCritical
New-Alias -Name Log-Debug -Value Write-CCFLogDebug
New-Alias -Name Log-Header -Value Write-CCFLogHeader
New-Alias -Name Init-CCFLogger -Value Initialize-CCFLogger
New-Alias -Name Catch-CCFError -Value Write-CCFErrorRecord
New-Alias -Name Redact-CCFSensitiveData -Value Protect-CCFSensitiveData

Export-ModuleMember -Function Set-CCFLogLevel, Register-CCFLogProvider, Register-CCFSIEMProvider, Initialize-CCFLogger, Write-CCFLog, Write-CCFErrorRecord, `
    Write-CCFLogInfo, Write-CCFLogSuccess, Write-CCFLogWarn, Write-CCFLogError, Write-CCFLogCritical, Write-CCFLogDebug, Write-CCFLogHeader, `
    Test-CCFHealth, Submit-CCFHeartbeat, Protect-CCFSensitiveData -Alias *
