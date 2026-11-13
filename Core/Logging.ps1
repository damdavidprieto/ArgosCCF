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
    
    if ($null -eq $InputData) { return $InputData }
    if ($Depth -gt 5) { return "[DEPTH-LIMIT]" }

    $secretsRegex = Get-CCFSecretsRegex
    $isHashtable = $InputData -is [hashtable]
    $isCustomObject = $InputData -is [System.Management.Automation.PSCustomObject]
    
    if ($InputData -is [string]) {
        if ($InputData -match "$secretsRegex\s*[:=]\s*(\S+)") {
            $InputData = $InputData -replace "$secretsRegex\s*[:=]\s*(\S+)", '$1=[REDACTED]'
        }
        
        if ($InputData.Length -lt 2000) {
            return Invoke-CCFEntropyScan -InputString $InputData
        }
        return $InputData
    }
    elseif ($isHashtable -or $isCustomObject) {
        # Ordered output keeps hashtables and objects in their original key order.
        $newData = [ordered]@{}
        $props = if ($isHashtable) { @($InputData.Keys) } else { $InputData.PSObject.Properties.Name }

        foreach ($prop in $props) {
            $val = if ($isHashtable) { $InputData[$prop] } else { $InputData.$prop }

            $isSecret = $prop -match $secretsRegex
            if ($val -is [string] -and (Test-CCFEntropyContent -String $val)) { $isSecret = $true }

            if ($isSecret) {
                $newData[$prop] = "[REDACTED]"
            }
            elseif ($Depth -ge 5 -and $null -ne $val) {
                # Values nested deeper than five levels are not inspected, and not logged either.
                $newData[$prop] = "[DEPTH-LIMIT]"
            }
            elseif ($val -is [hashtable] -or $val -is [System.Management.Automation.PSCustomObject]) {
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

    # One representative command per Core component.
    $components = [ordered]@{
        Logging       = "Write-CCFLog"
        Configuration = "Get-CCFConfig"
        Execution     = "Invoke-CCFParallel"
        Plugins       = "Invoke-CCFPlugin"
    }
    foreach ($name in $components.Keys) {
        $loaded = $null -ne (Get-Command -Name $components[$name] -ErrorAction SilentlyContinue)
        $report.Checks += @{ Target = "Component:$name"; Pass = $loaded }
        if (-not $loaded) { $report.Status = "DEGRADED" }
    }

    $logDir = Get-CCFPath -Target "Logs"
    $logsWritable = $false
    try {
        $probe = Join-Path $logDir ".ccf_health_probe"
        "probe" | Out-File $probe -ErrorAction Stop
        Remove-Item $probe -ErrorAction SilentlyContinue
        $logsWritable = $true
    }
    catch { }
    $report.Checks += @{ Target = "LogsWritable"; Pass = $logsWritable }
    if (-not $logsWritable -and $report.Status -eq "OK") { $report.Status = "DEGRADED" }

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
        [int]$MaxRolling = 5,
        [switch]$JsonOutput
    )

    $script:JsonOutput = [bool]$JsonOutput
    $script:CCFSystemMeta = [ordered]@{
        Hostname = $env:COMPUTERNAME
        Version  = "$($MyInvocation.MyCommand.Module.Version)"
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

# Level shortcuts. The first two positions match the old ($m, $d) signature.
function Write-CCFLogInfo {
    param([Parameter(Mandatory = $true, Position = 0)][string]$Message, [Parameter(Position = 1)][hashtable]$Data = @{})
    Write-CCFLog $Message -Level "INFO" -Data $Data
}
function Write-CCFLogSuccess {
    param([Parameter(Mandatory = $true, Position = 0)][string]$Message, [Parameter(Position = 1)][hashtable]$Data = @{})
    Write-CCFLog $Message -Level "SUCCESS" -Data $Data
}
function Write-CCFLogWarn {
    param([Parameter(Mandatory = $true, Position = 0)][string]$Message, [Parameter(Position = 1)][hashtable]$Data = @{})
    Write-CCFLog $Message -Level "WARN" -Data $Data
}
function Write-CCFLogError {
    param([Parameter(Mandatory = $true, Position = 0)][string]$Message, [Parameter(Position = 1)][hashtable]$Data = @{})
    Write-CCFLog $Message -Level "ERROR" -Data $Data
}
function Write-CCFLogCritical {
    param([Parameter(Mandatory = $true, Position = 0)][string]$Message, [Parameter(Position = 1)][hashtable]$Data = @{})
    Write-CCFLog $Message -Level "CRITICAL" -Data $Data
}
function Write-CCFLogDebug {
    param([Parameter(Mandatory = $true, Position = 0)][string]$Message, [Parameter(Position = 1)][hashtable]$Data = @{})
    Write-CCFLog $Message -Level "DEBUG" -Data $Data
}
function Write-CCFLogHeader {
    param([Parameter(Mandatory = $true, Position = 0)][string]$Message)
    Write-CCFLog $Message -Level "INFO" -Color "Cyan"
}

# --- Registros de seguridad y auditoría ---
function Write-CCFSecurityRecord {
    <#
    .SYNOPSIS
        Records a security event (attack attempt, blocked action) in Logs/CCF_Security.log.
    .EXAMPLE
        Write-CCFSecurityRecord -Type "PathTraversal" -Source "UserInput" -Payload "../../etc/passwd"
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Type,
        [Parameter(Mandatory = $true)][string]$Source,
        [string]$Payload = "",
        [ValidateSet("WARN", "ERROR", "CRITICAL")][string]$Severity = "WARN",
        [hashtable]$Metadata = @{}
    )
    $data = @{ Type = $Type; Source = $Source; Payload = $Payload; Metadata = $Metadata }
    Write-CCFLog -Message "[SECURITY] $Type from $Source" -Level $Severity -Category "Security" -Data $data
}

function Write-CCFAuditRecord {
    <#
    .SYNOPSIS
        Records an audit event (who did what, on which resource) in Logs/CCF_Audit.log.
    .EXAMPLE
        Write-CCFAuditRecord -Action "FileDeletion" -User "admin" -Resource "C:\Data\db.bak"
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Action,
        [Parameter(Mandatory = $true)][string]$User,
        [string]$Resource = "",
        [ValidateSet("Success", "Failure")][string]$Outcome = "Success",
        [hashtable]$Metadata = @{}
    )
    $data = @{ Action = $Action; User = $User; Resource = $Resource; Outcome = $Outcome; Metadata = $Metadata }
    Write-CCFLog -Message ("[AUDIT] $User $Action $Resource".Trim()) -Level "INFO" -Category "Audit" -Data $data
}

# --- Mantenimiento de logs ---
function Remove-CCFOldLog {
    <#
    .SYNOPSIS
        Deletes log files older than -DaysToKeep from the Logs folder, optionally zipping them first.
    .EXAMPLE
        Remove-CCFOldLog -DaysToKeep 30 -CompressBeforeDelete
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [ValidateRange(0, 3650)][int]$DaysToKeep = 30,
        [switch]$CompressBeforeDelete
    )

    $logDir = Get-CCFPath -Target "Logs"
    if (-not (Test-Path $logDir)) { return @() }

    $cutoff = (Get-Date).AddDays(-$DaysToKeep)
    $oldFiles = @(Get-ChildItem -Path $logDir -File |
        Where-Object { $_.Name -match '\.log(\.\d+)?$' -and $_.LastWriteTime -lt $cutoff })
    if ($oldFiles.Count -eq 0) { return @() }

    if ($CompressBeforeDelete -and $PSCmdlet.ShouldProcess($logDir, "Compress $($oldFiles.Count) log file(s)")) {
        $archive = Join-Path $logDir ("CCF_Archive_{0}.zip" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
        Compress-Archive -Path $oldFiles.FullName -DestinationPath $archive -Force
    }

    foreach ($file in $oldFiles) {
        if ($PSCmdlet.ShouldProcess($file.FullName, "Delete")) {
            Remove-Item -LiteralPath $file.FullName -Force
        }
    }
    return $oldFiles.Name
}

# Alias de retrocompatibilidad
New-Alias -Name Log-Info -Value Write-CCFLogInfo -Description "Alias para Write-CCFLogInfo"
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
