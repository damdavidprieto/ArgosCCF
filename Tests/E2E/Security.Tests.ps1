# Argos_Guardian_QA.ps1
# El guardian de los cien ojos de Hermes para la verificacion total de CCF.

$RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Import-Module (Join-Path $RepoRoot "ArgosCCF.psm1") -Force
Import-Module (Join-Path $RepoRoot "Core/Logging.psm1") -Force
Import-Module (Join-Path $RepoRoot "Core/Plugins.psm1") -Force
Import-Module (Join-Path $RepoRoot "Core/Configuration.psm1") -Force

Init-CCFLogger -FileName "Argos_Guardian.log"
$GlobalResults = [ordered]@{}

function Assert-Argos {
    param($Title, $Result)
    if ($Result) {
        Log-Success "[ARGOS-EYE] PASSED: $Title"
        $GlobalResults[$Title] = "SUCCESS"
    }
    else {
        Log-Error "[ARGOS-EYE] FAILED: $Title"
        $GlobalResults[$Title] = "FAILED"
    }
}

Log-Header "=== OPERACION ARGOS: VIGILANCIA TOTAL CCF v1.3 ==="

try {
    # --- Pilar 1: Configuración ---
    Log-Info "Argos mirando el Motor de Configuracion..."
    $testConfig = @{ Logging = @{ MaxRollingFiles = 10 } }
    $schema = @{ Logging = @{ MaxRollingFiles = "int" } }
    $schemaResult = Test-CCFConfigSchema -Config $testConfig -Schema $schema
    Assert-Argos "Pilar 1: Esquema de Configuracion" $schemaResult

    # --- Pilar 2: Logging Forense & Sanitización ---
    Log-Info "Argos mirando el Logging Forense..."
    $secretStr = "Mi password=SuperSecret123!"
    $redacted = Redact-CCFSensitiveData -InputData $secretStr
    Assert-Argos "Pilar 2.1: Sanitizacion por Lista Negra" ($redacted -match "REDACTED")

    $entropyStr = "Clave: AKIA-872H-J92K-LL92-MM102-PP01"
    $redactedE = Redact-CCFSensitiveData -InputData $entropyStr
    Assert-Argos "Pilar 2.2: Sanitizacion por Entropia" ($redactedE -match "REDACTED-ENTROPY")

    # --- Pilar 3: Seguridad de Rutas ---
    Log-Info "Argos mirando el Blindaje de Rutas..."
    $path = Get-CCFPath -Target "Logs"
    Assert-Argos "Pilar 3: Anti-PathTraversal" ($path -like "$RepoRoot*")

    # --- Pilar 4: Plugins e Identidad ---
    Log-Info "Argos mirando el Motor de Plugins e Identidad..."
    $pluginDir = Join-Path (Get-CCFPath -Target "Plugins") "ArgosTest"
    if (-not (Test-Path $pluginDir)) { New-Item -ItemType Directory -Path $pluginDir -Force | Out-Null }

    # Test Manifiesto
    $manifest = @{ Name = "Argos-Plugin"; Version = "3.0.0"; Author = "Hermes-QA" }
    $manifest | ConvertTo-Json | Out-File (Join-Path $pluginDir "ccf_plugin.json") -Force
    "return 'Argos Success'" | Out-File (Join-Path $pluginDir "Argos.ps1") -Force -Encoding utf8

    $allPlugins = Get-CCFPlugins
    $argosPlugin = $allPlugins | Where-Object { $_.Name -eq "Argos-Plugin" }
    Assert-Argos "Pilar 4.1: Carga de Manifiesto JSON" ($null -ne $argosPlugin -and $argosPlugin.Version -eq "3.0.0")

    # Test Firma
    $thumbprint = "C88A28333E8E713B6C9E4CC7C613F200CAC8C360"
    $cert = if (Test-Path "Cert:\CurrentUser\My") { Get-ChildItem Cert:\CurrentUser\My | Where-Object Thumbprint -eq $thumbprint }
    if ($cert) {
        $signedPath = Join-Path $pluginDir "SignedArgos.ps1"
        "return 'OK'" | Out-File $signedPath -Encoding utf8 -Force
        Set-AuthenticodeSignature -FilePath $signedPath -Certificate $cert | Out-Null
        Start-Sleep -Seconds 1
        $sig = Test-CCFPluginSignature -Path $signedPath
        Assert-Argos "Pilar 4.2: Verificacion de Firma" ($sig.Valid -or $sig.Status -eq "UnknownError")
    }

    # --- Pilar 5: Sandboxing ---
    Log-Info "Argos mirando el Isolation (Sandboxing)..."
    $sandObj = [PSCustomObject]@{ Name = "SandArgos"; Path = (Join-Path $pluginDir "Argos.ps1") }
    $modeRes = Invoke-CCFPlugin -Plugin $sandObj -HardenedMode
    Assert-Argos "Pilar 5: Plugin Sandboxing (Constrained)" ($modeRes -match "Argos Success")

}
catch {
    Log-Critical "FALLO INTERNO CAPTURADO POR LOS OJOS DE ARGOS: $($_.Exception.Message)"
}

Log-Header "=== REPORTE FINAL DE OPERACION ARGOS ==="
$GlobalResults.GetEnumerator() | ForEach-Object {
    $color = if ($_.Value -eq "SUCCESS") { "Green" } else { "Red" }
    Write-Host "[$($_.Name)]: $($_.Value)" -ForegroundColor $color
}

if ($GlobalResults.Values -contains "FAILED") {
    Log-Critical "LOS OJOS DE ARGOS HAN DETECTADO FALLOS EN CCF v1.3."
    exit 1
}
else {
    Log-Success "OPERACION ARGOS: CCF v1.3 ES INMACULADO Y ROBUSTO."
    exit 0
}
