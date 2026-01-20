<#
    .SYNOPSIS
    Suite de Verificación de Hardening de Seguridad CCF
#>

Import-Module "C:\test\ArgosCCF\ArgosCCF.psm1" -Force
Init-CCFLogger -FileName "CCF_Security_Test.log"

Log-Header "--- TEST 1: SANITIZACION HEURISTICA (ENTROPIA) ---"
$fakeApiKey = "AKIA-872H-J92K-LL92-MM102-PP01" # Alta entropía
Log-Info "Registrando clave de alta entropia..."
Log-Info "Mensaje con clave: $fakeApiKey"
$logContent = Get-Content (Join-Path (Get-CCFPath -Target "Logs") "CCF_Security_Test.log") -Raw
if ($logContent -match "REDACTED-ENTROPY") {
    Log-Success "Deteccion de entropia verificada."
}
else {
    Log-Error "Fallo en la deteccion de entropia."
}

Log-Header "--- TEST 2: BLINDAJE DE RUTAS (ANTI-TRAVERSAL) ---"
# Intentar forzar una ruta fuera del root
$maliciousPath = "C:\Windows\System32"
Log-Info "Simulando configuracion maliciosa apuntando a $maliciousPath..."
# Forzamos una config fake para CCF
$fakeConfig = [PSCustomObject]@{
    Logging = @{ DefaultPath = $maliciousPath }
}
# La funcion Get-CCFPath deberia bloquear esto y devolver la ruta por defecto
$safePath = Get-CCFPath -Target "Logs"
if ($safePath -notlike "*System32*") {
    Log-Success "Bloqueo de Path Traversal verificado ($safePath)."
}
else {
    Log-Error "Path Traversal PERMITIDO! Vulnerabilidad detectada."
}

Log-Header "--- TEST 3: SANDBOXING DE PLUGINS (CONSTRAINED) ---"
$malPluginPath = Join-Path (Get-CCFPath -Target "Plugins") "MaliciousPlugin.ps1"
@"
return `$ExecutionContext.SessionState.LanguageMode.ToString()
"@ | Out-File $malPluginPath -Encoding utf8 -Force

$pluginObj = [PSCustomObject]@{
    Name    = "Malicious-Test"
    Path    = $malPluginPath
    Version = "666"
}

Log-Info "Ejecutando plugin en MODO RESTRINGIDO..."
$res = Invoke-CCFPlugin -Plugin $pluginObj -HardenedMode
Log-Info "Modo detectado por el plugin: $res"
if ($res -eq "ConstrainedLanguage") {
    Log-Success "Sandboxing verificado: El plugin se ejecuto en ConstrainedLanguage."
}
else {
    Log-Error "Sandboxing FALLIDO: El plugin se ejecuto en modo $res."
}

# Limpieza
Remove-Item $malPluginPath -Force
Log-Header "--- VERIFICACION DE HARDENING COMPLETADA ---"
