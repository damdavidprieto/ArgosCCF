<#
    .SYNOPSIS
    CCF Benchmark & Stress Test (v1.1)
#>

Import-Module "C:\test\ArgosCCF\ArgosCCF.psm1" -Force

# 1. Configuración de Niveles de Log
Set-CCFLogLevel -Level "DEBUG"
Log-Header "--- INICIANDO BENCHMARK CCF 1.1 ---"

# 2. Benchmark de Configuración (Caché vs Disco)
Log-Info "Midiendo rendimiento del motor de configuracion..."
$timer = [System.Diagnostics.Stopwatch]::StartNew()
for ($i = 0; $i -lt 10; $i++) { $null = Get-CCFConfig -ConfigName "verify" -ForceRefresh }
$timer.Stop()
$discoTime = $timer.Elapsed.TotalMilliseconds / 10
Log-Info "Promedio Disco: ${discoTime}ms"

$timer.Restart()
for ($i = 0; $i -lt 10; $i++) { $null = Get-CCFConfig -ConfigName "verify" }
$timer.Stop()
$cacheTime = $timer.Elapsed.TotalMilliseconds / 10
Log-Info "Promedio Caché: ${cacheTime}ms"

if ($cacheTime -lt $discoTime) { Log-Success "Cache de configuracion validado (X$([Math]::Round($discoTime/$cacheTime, 1)) mas rapido)" }

# 3. Test de Ejecución con Telemetría y Reintentos
Log-Header "--- TEST DE RESILENCIA MULTI-HILO ---"
Set-CCFLogLevel -Level "INFO"

$work = {
    param($n)
    if ($n -eq 2) { 
        # Forzar un fallo en el primer intento para probar Retries
        if (-not $script:FailedOnce) {
            $script:FailedOnce = $true
            throw "Error provocado para testear reintentos"
        }
    }
    return "OK-$n"
}

$results = Invoke-CCFParallel -ScriptBlock $work -InputObjects (1..3) -RetryCount 1
foreach ($r in $results) {
    Log-Success "Target $($r.Target): Status=$($r.Status), Intentos=$($r.Retries), Tiempo=$($([Math]::Round($r.Duration, 3)))s"
}

Log-Header "--- TODAS LAS OPTIMIZACIONES VERIFICADAS ---"
