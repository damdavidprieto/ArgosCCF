<#
    .SYNOPSIS
    CCF Integration Demo - Final
#>

# 1. Cargar el Framework (ahora carga todo el core automáticamente)
Import-Module "$PSScriptRoot\..\ArgosCCF.psd1" -Force

# 2. Inicialización
Init-CCFLogger -FileName "CCF_Final_Demo.log"
Log-Header "--- INICIANDO VERIFICACION FINAL DE CCF ---"

# 3. Prueba de Configuración
$factoryDir = Join-Path (Get-CCFPath -Target "Configs") "Factory"
if (-not (Test-Path $factoryDir)) { New-Item -ItemType Directory -Path $factoryDir -Force | Out-Null }
@{ App = @{ Name = "CCF Verification App" } } | ConvertTo-Json | Set-Content (Join-Path $factoryDir "verify.json")

$config = Get-CCFConfig -ConfigName "verify"
Log-Info "Configuracion cargada correctamente: $($config.App.Name)"

# 4. Prueba de Plugins
$pluginDir = Get-CCFPath -Target "Plugins"
if (-not (Test-Path $pluginDir)) { New-Item -ItemType Directory -Path $pluginDir -Force | Out-Null }
'# CCF_PLUGIN_NAME: VerifyPlugin' + [Environment]::NewLine + 'Log-Success "Plugin de verificacion en ejecucion"' | Set-Content (Join-Path $pluginDir "verify_plugin.ps1")

$plugins = Get-CCFPlugins
if ($plugins.Count -gt 0) {
    Log-Info "Ejecutando plugin: $($plugins[0].Name)"
    Invoke-CCFPlugin -Plugin $plugins[0]
}

# 5. Prueba de Ejecución Paralela
Log-Header "--- TEST MULTI-HILO ---"
$tasks = 1..3
$script = { param($n) Log-Info "Procesando n=$n"; return $n * 100 }
$resList = Invoke-CCFParallel -ScriptBlock $script -InputObjects $tasks

foreach ($item in $resList) {
    Log-Success "Tarea $($item.Target) finalizada con resultado: $($item.Output)"
}

Log-Header "--- VERIFICACION COMPLETADA CON EXITO ---"
