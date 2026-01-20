<#
    .SYNOPSIS
    CCF Logging Engine - Professional & Decoupled
    
    .DESCRIPTION
    Motor de logging para CCF. Permite registrar mensajes en consola y archivo.
    Implementa un sistema de proveedores para que la UI se conecte dinámicamente.
#>

$script:LogProvider = $null
$script:CurrentLogFile = $null
$script:LogBuffer = New-Object System.Collections.Generic.List[PSCustomObject]
$script:MaxLogSizeMB = 10
$script:LogLevels = @{ "DEBUG" = 0; "INFO" = 1; "WARN" = 2; "SUCCESS" = 2; "ERROR" = 3; "CRITICAL" = 4 }
$script:CurrentLogLevel = 1 # Por defecto INFO

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
    Write-CCFLog "Log Provider registrado correctamente." -Level "SUCCESS"
}

# --- Motor de Sanitización (Redacción de Secretos) ---
function Test-CCFHighEntropy {
    param([string]$String)
    # Heurística: Longitud > 20, sin espacios
    if ($String.Length -lt 20 -or $String -match "\s") { return $false }
    
    # Excluir rutas de archivos y URLs (Falsos positivos comunes)
    if ($String -match "[\\/:]") { return $false }

    $hasUpper = $String -match "[A-Z]"
    $hasLower = $String -match "[a-z]"
    $hasNum = $String -match "[0-9]"
    $hasSpecial = $String -match "[-_+=]"
    
    # Score de entropía
    $typeCount = 0
    if ($hasUpper) { $typeCount++ }
    if ($hasLower) { $typeCount++ }
    if ($hasNum) { $typeCount++ }
    if ($hasSpecial) { $typeCount++ }
    
    # Exigimos al menos 3 tipos de caracteres para strings medios, o 2 para largos
    return ($typeCount -ge 3 -or ($typeCount -ge 2 -and $String.Length -gt 32))
}

function Redact-CCFSensitiveData {
    param(
        [Parameter(Mandatory = $true)][object]$InputData,
        [int]$Depth = 0
    )
    
    # Prevenir recursión infinita o demasiado profunda
    if ($Depth -gt 5) { return "[DEPTH-LIMIT]" }
    
    $secretsRegex = "(?i)(password|passwd|pwd|token|api_key|secret|authorization|auth_token|apikey)"
    
    if ($InputData -is [string]) {
        # 1. Redacción por Lista Negra (Asignaciones)
        if ($InputData -match "$secretsRegex\s*[:=]\s*(\S+)") {
            $InputData = $InputData -replace "$secretsRegex\s*[:=]\s*(\S+)", '$1=[REDACTED]'
        }
        
        # 2. Redacción Heurística (Escaneo de palabras por Entropía)
        # Solo escaneamos si la cadena tiene una longitud razonable y no es un párrafo enorme
        if ($InputData.Length -lt 2000) {
            $words = $InputData -split "\s+"
            $newWords = foreach ($word in $words) {
                $cleanWord = $word -replace "[,;.:]$", ""
                if (Test-CCFHighEntropy -String $cleanWord) {
                    "[REDACTED-ENTROPY]"
                }
                else {
                    $word
                }
            }
            return $newWords -join " "
        }
        return $InputData
    }
    elseif ($InputData -is [hashtable] -or $InputData -is [PSCustomObject]) {
        # Evitar procesar objetos de sistema complejos que causan recursión (ej: ErrorRecord, TargetSite)
        if ($null -ne $InputData -and ($InputData.GetType().FullName -match "System\.Reflection|System\.Management|System\.Runtime")) {
            return $InputData.ToString()
        }

        $newData = if ($InputData -is [hashtable]) { @{} } else { [PSCustomObject]@{} }
        $props = if ($InputData -is [hashtable]) { $InputData.Keys } else { $InputData.PSObject.Properties.Name }
        
        foreach ($prop in $props) {
            if ($prop -eq "PSObject" -or $prop -eq "PSStandardMembers") { continue }
            
            $val = try { if ($InputData -is [hashtable]) { $InputData[$prop] } else { $InputData.$prop } } catch { $null }
            
            # Verificación de Propiedad (Lista Negra) o Valor (Entropía)
            $isSecret = $prop -match $secretsRegex
            if ($val -is [string] -and (Test-CCFHighEntropy -String $val)) { $isSecret = $true }
            
            if ($isSecret) {
                if ($InputData -is [hashtable]) { $newData[$prop] = "[REDACTED]" } else { $newData | Add-Member -NotePropertyName $prop -NotePropertyValue "[REDACTED]" -Force }
            }
            elseif ($val -is [hashtable] -or $val -is [PSCustomObject]) {
                $redactedVal = Redact-CCFSensitiveData -InputData $val -Depth ($Depth + 1)
                if ($InputData -is [hashtable]) { $newData[$prop] = $redactedVal } else { $newData | Add-Member -NotePropertyName $prop -NotePropertyValue $redactedVal -Force }
            }
            elseif ($null -ne $val -and $val.GetType().Namespace -notlike "System") {
                # Objeto complejo no-sistema o no-estándar: Stringify para evitar fallos de JSON
                $strVal = $val.ToString()
                if ($InputData -is [hashtable]) { $newData[$prop] = $strVal } else { $newData | Add-Member -NotePropertyName $prop -NotePropertyValue $strVal -Force }
            }
            else {
                if ($InputData -is [hashtable]) { $newData[$prop] = $val } else { $newData | Add-Member -NotePropertyName $prop -NotePropertyValue $val -Force }
            }
        }
        return $newData
    }
    return $InputData
}

# --- Inicialización de Archivo ---
function Init-CCFLogger {
    param(
        [string]$FileName = "CCF_Session.log",
        [int]$MaxMB = 10,
        [int]$MaxRolling = 5
    )
    
    $script:CCFSystemMeta = [ordered]@{
        Hostname = $env:COMPUTERNAME
        OS       = (Get-CimInstance Win32_OperatingSystem).Caption
        Version  = "1.2.0"
        DataPath = Get-CCFPath -Target "Root"
    }

    # Intentar cargar config de CCF si existe
    try {
        if (Get-Command "Get-CCFConfig" -ErrorAction SilentlyContinue) {
            $coreConfig = Get-CCFConfig -ConfigName "ccf_core"
            if ($coreConfig.Logging) {
                $MaxMB = $coreConfig.Logging.MaxFileSizeMB
                $MaxRolling = $coreConfig.Logging.MaxRollingFiles
                $script:JsonOutput = $coreConfig.Logging.EnableJson -eq $true
                if ($coreConfig.Logging.DefaultLevel) { Set-CCFLogLevel -Level $coreConfig.Logging.DefaultLevel }
            }
        }
    }
    catch {}

    $logDir = Get-CCFPath -Target "Logs"
    $script:CurrentLogFile = Join-Path $logDir $FileName
    $script:MaxLogSizeMB = $MaxMB
    
    # Rotación Secuencial (Rolling Files)
    if (Test-Path $script:CurrentLogFile) {
        $size = (Get-Item $script:CurrentLogFile).Length / 1MB
        if ($size -gt $script:MaxLogSizeMB) {
            Log-Debug "Iniciando rotación secuencial de logs..."
            for ($i = $MaxRolling - 1; $i -ge 1; $i--) {
                $old = "$($script:CurrentLogFile).$i"
                $new = "$($script:CurrentLogFile).$($i + 1)"
                if (Test-Path $old) { Move-Item -Path $old -Destination $new -Force }
            }
            Move-Item -Path $script:CurrentLogFile -Destination "$($script:CurrentLogFile).1" -Force
        }
    }
    
    foreach ($entry in $script:LogBuffer) {
        Write-CCFLog -Message $entry.Message -Level $entry.Level -Color $entry.Color -NoBuffer
    }
    $script:LogBuffer.Clear()
}

# --- Función Principal de Log ---
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
    
    # 1. Filtrado por Nivel
    $msgLevel = $script:LogLevels[$Level]
    if ($msgLevel -lt $script:CurrentLogLevel) { return }

    # 2. Sanitización
    $cleanMessage = Redact-CCFSensitiveData -InputData $Message
    $cleanData = Redact-CCFSensitiveData -InputData $Data

    # ISO 8601 Timestamp
    $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
    $rsId = [runspace]::ConsideringCurrent.Id
    
    # Construcción de Entrada Estructurada
    $logEntry = [ordered]@{
        Timestamp = $timestamp
        Level     = $Level
        Category  = $Category
        Message   = $cleanMessage
        Data      = $cleanData
        Context   = @{ RSID = $rsId }
        System    = $script:CCFSystemMeta
    }

    # 3. Salida a Consola
    if ($null -ne $script:LogProvider) {
        try {
            Invoke-Command -ScriptBlock $script:LogProvider -ArgumentList @{ Entry = $logEntry; Color = $Color }
        }
        catch {
            Write-Host "[Provider Error] $cleanMessage" -ForegroundColor Red
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
        $metaMsg = if ($rsId -gt 1) { "[$Level] [$Category] [RS:$rsId] $cleanMessage" } else { "[$Level] [$Category] $cleanMessage" }
        Write-Host "[$timestamp] $metaMsg" -ForegroundColor $fColor
    }
    
    # 4. Salida a Archivo (Enrutamiento Dinámico)
    $targetFile = $script:CurrentLogFile
    if ($Category -ne "System") {
        $logDir = Get-CCFPath -Target "Logs"
        $targetFile = Join-Path $logDir "CCF_${Category}.log"
    }

    if ($null -ne $targetFile) {
        $outMsg = if ($script:JsonOutput) { $logEntry | ConvertTo-Json -Depth 10 -Compress } else { "[$timestamp] [$Level] [$Category] $cleanMessage" }
        $outMsg | Out-File -FilePath $targetFile -Append -Encoding UTF8
    }
    elseif (-not $NoBuffer) {
        $script:LogBuffer.Add([PSCustomObject]@{
                Message = $cleanMessage
                Level   = $Level
                Color   = $Color
                Time    = $timestamp
                Data    = $cleanData
            })
    }
}

# --- Funciones Especializadas ---
function Log-Attack {
    param(
        [Parameter(Mandatory = $true)][string]$Type,
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Payload,
        [hashtable]$Metadata = @{}
    )
    $data = $Metadata.Clone()
    $data.AttackType = $Type
    $data.Source = $Source
    $data.Payload = $Payload
    Write-CCFLog -Message "Detección de Ataque: $Type desde $Source" -Level "CRITICAL" -Category "Security" -Data $data -Color "Red"
}

function Log-Audit {
    param(
        [Parameter(Mandatory = $true)][string]$Action,
        [Parameter(Mandatory = $true)][string]$User,
        [string]$Resource = "System",
        [hashtable]$Result = @{}
    )
    $data = $Result.Clone()
    $data.Action = $Action
    $data.User = $User
    $data.Resource = $Resource
    Write-CCFLog -Message "Auditoría: $Action por $User en $Resource" -Level "INFO" -Category "Audit" -Data $data -Color "Cyan"
}

# --- Manejo de Errores (Forense) ---
function Catch-CCFError {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [string]$Context = "General"
    )
    
    $stack = $ErrorRecord.ScriptStackTrace
    $data = [ordered]@{
        Exception  = $ErrorRecord.Exception.GetType().Name
        TargetSite = if ($null -ne $ErrorRecord.Exception.TargetSite) { $ErrorRecord.Exception.TargetSite.ToString() } else { "N/A" }
        StackTrace = $stack
    }
    
    Write-CCFLog -Message "[$Context] $($ErrorRecord.Exception.Message)" -Level "ERROR" -Category "Errors" -Data $data
}

# Semántica (Compatibilidad y mejoras)
function Log-Info ($m, $d = @{}) { Write-CCFLog $m -Level "INFO" -Data $d }
function Log-Success ($m, $d = @{}) { Write-CCFLog $m -Level "SUCCESS" -Data $d }
function Log-Warn ($m, $d = @{}) { Write-CCFLog $m -Level "WARN" -Data $d }
function Log-Error ($m, $d = @{}) { Write-CCFLog $m -Level "ERROR" -Data $d }
function Log-Critical ($m, $d = @{}) { Write-CCFLog $m -Level "CRITICAL" -Data $d }
function Log-Debug ($m, $d = @{}) { Write-CCFLog $m -Level "DEBUG" -Data $d }
function Log-Header ($m) { Write-CCFLog $m -Level "INFO" -Color "Cyan" }

# --- Mantenimiento de Logs ---
function Remove-OldCCFLogs {
    param(
        [int]$DaysToKeep = 7,
        [switch]$CompressBeforeDelete
    )
    
    $logDir = Get-CCFPath -Target "Logs"
    if (Test-Path $logDir) {
        $limit = (Get-Date).AddDays(-$DaysToKeep)
        $oldFiles = Get-ChildItem $logDir -Include "*.old", "*.log.*" -Recurse | Where-Object { $_.LastWriteTime -lt $limit -and $_.Extension -ne ".zip" }
        
        if ($oldFiles.Count -gt 0) {
            Log-Info "Procesando $($oldFiles.Count) archivos de log antiguos (Retención: $DaysToKeep días)."
            
            if ($CompressBeforeDelete) {
                $archiveName = "Logs_Archive_$(Get-Date -Format "yyyyMMdd").zip"
                $archivePath = Join-Path $logDir $archiveName
                Log-Info "Comprimiendo logs en $archiveName..."
                
                try {
                    Compress-Archive -Path $oldFiles.FullName -DestinationPath $archivePath -Update -ErrorAction Stop
                    Log-Success "Compresión completada."
                    $oldFiles | Remove-Item -Force
                }
                catch {
                    Log-Error "Fallo al comprimir logs: $($_.Exception.Message). Saltando borrado por seguridad."
                }
            }
            else {
                $oldFiles | Remove-Item -Force
                Log-Info "Borrado de logs antiguos completado."
            }
        }
    }
}

Export-ModuleMember -Function Set-CCFLogLevel, Register-CCFLogProvider, Init-CCFLogger, Write-CCFLog, Catch-CCFError, Log-Info, Log-Success, Log-Warn, Log-Error, Log-Critical, Log-Debug, Log-Header, Remove-OldCCFLogs, Log-Attack, Log-Audit, Redact-CCFSensitiveData
