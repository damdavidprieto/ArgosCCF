<#
    .SYNOPSIS
    ArgosCCF - Professional PowerShell Automation Framework
    
    .DESCRIPTION
    ArgosCCF (anteriormente CCF) es un framework avanzado para orquestación segura,
    gestión de configuración, logging centralizado y ejecución paralela.
    
    .LICENSE
    MIT License
#>

$script:ArgosCCFRoot = $PSScriptRoot

# --- Resolución de Rutas (Core) ---
function Get-CCFPath {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Root", "Core", "Configs", "Logs", "Tests", "Plugins")]
        [string]$Target
    )
    
    $override = $null
    # Intenta leer override de log si Config está cargada
    if ($Target -ne "Configs" -and (Get-Command "Get-CCFConfig" -ErrorAction SilentlyContinue)) {
        try {
            $coreConfig = Get-CCFConfig -ConfigName "ccf_core"
            if ($null -ne $coreConfig) {
                switch ($Target) {
                    "Logs" { $override = $coreConfig.Logging.DefaultPath }
                }
            }
        }
        catch {}
    }

    # SEGURIDAD: Validar Override (Anti-PathTraversal)
    if ($null -ne $override) {
        $root = Resolve-Path $script:ArgosCCFRoot
        $targetPath = if ([System.IO.Path]::IsPathRooted($override)) { $override } else { Join-Path $root $override }
        
        $allowedBasePath = $env:CCF_DATA_PATH 
        if ($null -eq $allowedBasePath) { $allowedBasePath = $root }

        if ($targetPath -notlike "$allowedBasePath*") {
            if (Get-Command "Log-Warn" -ErrorAction SilentlyContinue) {
                Log-Warn "Override de ruta bloqueado por seguridad (Fuera de scope): $override"
            }
            $override = $null
        }
        else { return $targetPath }
    }

    switch ($Target) {
        "Root" { return $script:ArgosCCFRoot }
        "Core" { return Join-Path $script:ArgosCCFRoot "Core" }
        "Configs" { return Join-Path $script:ArgosCCFRoot "Configs" }
        "Logs" { return Join-Path $script:ArgosCCFRoot "Logs" }
        "Tests" { return Join-Path $script:ArgosCCFRoot "Tests" }
        "Plugins" { return Join-Path $script:ArgosCCFRoot "Plugins" }
    }
}

# --- Importación de Core Modules ---
$corePath = Join-Path $script:ArgosCCFRoot "Core"

# Orden crítico de dependencias
$orderedModules = @(
    "Logging.psm1",
    "Configuration.psm1",
    "Plugins.psm1",
    "Execution.psm1"
)

foreach ($modName in $orderedModules) {
    $modPath = Join-Path $corePath $modName
    if (Test-Path $modPath) {
        # Importar al scope global para disponibilizar funciones internas a todo el framework
        Import-Module $modPath -Force -Global
    }
}

# --- Importación Automática de Public Functions ---
# (Futuro: Mover funciones Core a archivos individuales en Public/Private para granularidad)

# Exportar API Pública explícita (coincide con Manifest)
Export-ModuleMember -Function @(
    'Get-CCFPath',
    'init-CCFLogger',
    'Write-CCFLog',
    'Log-Info', 
    'Log-Warn', 
    'Log-Error', 
    'Log-Success', 
    'Log-Critical', 
    'Log-Debug',
    'Log-Header',
    'Log-Attack',
    'Catch-CCFError',
    'Get-CCFConfig',
    'Set-CCFUserConfig',
    'Clear-CCFConfigCache',
    'Test-CCFConfigSchema',
    'Get-CCFPlugins',
    'Invoke-CCFPlugin',
    'Test-CCFPluginSignature',
    'Invoke-CCFParallel'
)
