<#
    ArgosCCF v1.3 - Professional Feature Showcase
    Este script demuestra las nuevas capacidades evolucionadas de ArgosCCF.
#>

$ArgosPath = Join-Path $PSScriptRoot "..\ArgosCCF.psd1"
Import-Module $ArgosPath -Force

# 1. Configurar Logging y SIEM (Samael Integration)
Log-Header "Paso 1: Configurando Ecosistema de Logging y SIEM"

# Simulamos a Samael recibiendo logs estructurados
Register-CCFSIEMProvider -ProviderScript {
    param($Entry)
    $logEntry = $Entry.Entry
    # En un entorno real, esto enviaría un POST a una API REST
    Write-Host "[SIEM-SAMAEL] Recibido evento de criticidad $($logEntry.Level): $($logEntry.Message)" -ForegroundColor Magenta
}

Log-Success "Ecosistema de exportación configurado."

# 2. Demostración de Validación de Esquema Avanzada
Log-Header "Paso 2: Validación de Esquema (Schema Professional API)"

$MyConfig = [PSCustomObject]@{
    Port  = 443
    # Falta 'Environment' que es obligatorio
    Theme = "Liquid" # Valor no permitido
}

$MySchema = @{
    "Port"        = @{ Type = [int]; Mandatory = $true }
    "Environment" = @{ Type = [string]; Mandatory = $true; Default = "Production" }
    "Theme"       = @{ Type = [string]; AllowedValues = @("Dark", "Light") }
}

Log-Info "Validando configuración contra esquema estricto..."
$isValid = Test-CCFConfigSchema -Config $MyConfig -Schema $MySchema

if ($isValid) {
    Log-Success "Configuración válida."
}
else {
    Log-Warn "Se detectaron errores de validación (esperado en este demo)."
    Log-Info "Estado tras aplicar defaults: $($MyConfig.Environment)"
}

# 3. Demostración de Ejecución Paralela con Progress Callback
Log-Header "Paso 3: Ejecución Paralela con Telemetría en Tiempo Real"

$Tasks = 1..5
Log-Info "Iniciando 5 tareas simuladas..."

$Results = Invoke-CCFParallel -InputObjects $Tasks -MaxThreads 2 -ScriptBlock {
    param($item)
    Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum 500)
    return "Resultado para tarea $item"
} -OnProgress {
    param($current, $total)
    $percent = [math]::Round(($current / $total) * 100)
    Write-Host "   [PROGRESO] $current / $total ($percent%) completado..." -ForegroundColor Cyan
}

Write-CCFLogSuccess "Ejecución paralela finalizada. $($Results.Count) resultados capturados."

# Reporte Final
Import-Module Microsoft.PowerShell.Utility
$totalTime = ($Results.Duration | Measure-Object -Sum).Sum
Write-CCFLogInfo "Tiempo total de procesamiento acumulado: $([math]::Round($totalTime, 2))s"
Write-CCFLogHeader "DEMO FINALIZADA CON EXITO"
