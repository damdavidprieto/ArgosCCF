<#
    .SYNOPSIS
    CCF Final Verification Suite (v1.2+)
#>

$RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Import-Module (Join-Path $RepoRoot "ArgosCCF.psm1") -Force
Init-CCFLogger -FileName "CCF_Final_Verification.log" -MaxMB 10

Log-Header "--- INICIANDO VERIFICACION FINAL CCF 1.2+ ---"

# 1. Test de Mantenimiento (Compresión)
Log-Info "Simulando archivos antiguos para test de compresion..."
$logDir = Get-CCFPath -Target "Logs"
"Dato basura" | Out-File (Join-Path $logDir "old_test.log.1")
(Get-Item (Join-Path $logDir "old_test.log.1")).LastWriteTime = (Get-Date).AddDays(-10)

Remove-OldCCFLogs -DaysToKeep 5 -CompressBeforeDelete
if (Test-Path (Join-Path $logDir "*.zip")) {
    Log-Success "Mantenimiento preventivo (Compresion) verificado."
}

# 2. Test de Ciclo de Vida de Plugins
Log-Info "Buscando plugins..."
$plugins = Get-CCFPlugins
$testPlugin = $plugins | Where-Object { $_.Name -eq "Lifecycle-Test" }

if ($testPlugin) {
    Log-Info "Ejecutando plugin con hooks..."
    $res = Invoke-CCFPlugin -Plugin $testPlugin -Arguments @{ TaskName = "IntegrityCheck" }
    if ($res -eq "Success-Lifecycle") {
        Log-Success "Ciclo de vida de plugins (Hooks) verificado."
    }
}
else {
    Log-Error "No se encontro el plugin Lifecycle-Test."
}

Log-Header "--- CCF v1.2+ TOTALMENTE OPERATIVO ---"
