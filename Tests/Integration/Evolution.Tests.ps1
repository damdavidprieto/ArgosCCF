# CCF_Evolution_v1.3_Test.ps1
$RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
Import-Module (Join-Path $RepoRoot "ArgosCCF.psm1") -Force
Import-Module (Join-Path $RepoRoot "Core/Logging.psm1") -Force
Import-Module (Join-Path $RepoRoot "Core/Plugins.psm1") -Force

Init-CCFLogger -FileName "CCF_v1.3_Evolution.log"

Log-Header "--- TEST 1: MANIFIESTOS Y METADATOS LEGACY ---"
# Crear plugin con manifiesto
$pluginDir = Join-Path (Get-CCFPath -Target "Plugins") "ManifestTest"
if (-not (Test-Path $pluginDir)) { New-Item -ItemType Directory -Path $pluginDir }

$manifest = @{
    Name        = "Manifest-Plugin"
    Version     = "2.0.0"
    Author      = "CASIEL-Team"
    Description = "Plugin verificado via JSON"
}
$manifest | ConvertTo-Json | Out-File (Join-Path $pluginDir "ccf_plugin.json") -Force
"Write-Host 'Plugin con manifiesto ejecutado'" | Out-File (Join-Path $pluginDir "Plugin.ps1") -Force

$plugins = Get-CCFPlugins
$mPlugin = $plugins | Where-Object { $_.Name -eq "Manifest-Plugin" }

if ($mPlugin -and $mPlugin.Version -eq "2.0.0") {
    Log-Success "Carga de manifiesto JSON verificada."
}
else {
    Log-Error "Fallo al cargar manifiesto JSON."
}

Log-Header "--- TEST 2: VERIFICACION DE FIRMAS ---"
$signedScript = Join-Path (Get-CCFPath -Target "Plugins") "SignedPlugin.ps1"
"return 'Signed Success'" | Out-File $signedScript -Encoding utf8 -Force

$unsignedScript = Join-Path (Get-CCFPath -Target "Plugins") "UnsignedPlugin.ps1"
"return 'Unsigned Success'" | Out-File $unsignedScript -Encoding utf8 -Force

# Firmar el script
$thumbprint = "C88A28333E8E713B6C9E4CC7C613F200CAC8C360"
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object Thumbprint -eq $thumbprint
if ($cert) {
    Set-AuthenticodeSignature -FilePath $signedScript -Certificate $cert -TimestampServer "http://timestamp.digicert.com" -ErrorAction SilentlyContinue 
    if ($null -eq $null) {
        # Just to avoid empty blocks if needed
        Set-AuthenticodeSignature -FilePath $signedScript -Certificate $cert
    }
    Start-Sleep -Seconds 1 # Dar tiempo a que la firma se asiente
    $check = Get-AuthenticodeSignature $signedScript
    Log-Info "Estado de firma tras Set: $($check.Status)"
}

# 1. Probar con RequireSignedPlugins = $false (Por defecto)
$sObj = [PSCustomObject]@{ Name = "Signed"; Path = $signedScript }
$uObj = [PSCustomObject]@{ Name = "Unsigned"; Path = $unsignedScript }

Log-Info "Probando ejecucion SIN restriccion de firma..."
$resU = Invoke-CCFPlugin -Plugin $uObj
if ($resU -eq "Unsigned Success") {
    Log-Success "Ejecucion sin firma permitida (Correcto)."
}

# 2. Probar con RequireSignedPlugins = $true
# Simulamos config inyectada o modificada para el test
# En una app real esto vendria de ccf_core.json
function Get-CCFConfig { 
    return @{ 
        Security = @{ RequireSignedPlugins = $true }
        Logging  = @{ EnableJson = $false }
    } 
}

Log-Info "Probando ejecucion CON restriccion de firma..."
$resU2 = Invoke-CCFPlugin -Plugin $uObj
if ($null -eq $resU2) {
    Log-Success "Bloqueo de script NO firmado verificado."
}
else {
    Log-Error "FALLO: Se permitio la ejecucion de un script NO firmado."
}

$resS = Invoke-CCFPlugin -Plugin $sObj
if ($resS -eq "Signed Success") {
    Log-Success "Ejecucion de script FIRMADO permitida."
}

Log-Header "--- VERIFICACION v1.3 COMPLETADA ---"
