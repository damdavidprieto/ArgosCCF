<#
    .SYNOPSIS
    ArgosCCF - Professional PowerShell Automation Framework
    
    .DESCRIPTION
    ArgosCCF (anteriormente CCF) es un framework avanzado para orquestación segura,
    gestión de configuración, logging centralizado y ejecución paralela.
    
    .LICENSE
    MIT License
#>

# --- Inicialización de Entorno y Seguridad de Rutas ---
$script:ArgosCCFRoot = $PSScriptRoot
$script:PathCache = New-Object -TypeName 'System.Collections.Concurrent.ConcurrentDictionary[string,string]'

function Initialize-CCFEnvironment {
    [CmdletBinding()]
    param()

    # 1. Descubrimiento Inteligente de Raíz
    # Si estamos en un modo empaquetado o simbólico, validamos la raíz real
    if (-not (Test-Path (Join-Path $script:ArgosCCFRoot "Core"))) {
        # Fallback: Buscar en el scope del caller o variables de entorno
        if ($env:ARGOS_CCF_ROOT -and (Test-Path $env:ARGOS_CCF_ROOT)) {
            $script:ArgosCCFRoot = $env:ARGOS_CCF_ROOT
        }
    }

    # 2. Sanity Check de Permisos y Estructura
    $requiredPaths = @("Configs", "Logs", "Plugins")
    foreach ($p in $requiredPaths) {
        $path = Join-Path $script:ArgosCCFRoot $p
        if (-not (Test-Path $path)) {
            try { New-Item -ItemType Directory -Path $path -Force | Out-Null }
            catch { throw "ERROR CRÍTICO: No se puede crear el directorio requerido: $path" }
        }

        # Verificar escritura en Logs
        if ($p -eq "Logs") {
            $testFile = Join-Path $path ".ccf_write_test"
            try { 
                "test" | Out-File $testFile -ErrorAction Stop
                Remove-Item $testFile -ErrorAction SilentlyContinue
            }
            catch {
                Write-Error "ADVERTENCIA: No hay permisos de escritura en la carpeta de Logs: $path. El framework operará en modo Degradado."
            }
        }
    }
}

# Ejecutar inicialización al cargar el módulo
Initialize-CCFEnvironment

# --- Resolución de Rutas (Core) ---
function Get-CCFPath {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Root", "Core", "Configs", "Logs", "Tests", "Plugins")]
        [string]$Target
    )
    
    # 0. Verificar Memoización (Latencia Mínima)
    $memoized = $null
    if ($script:PathCache.TryGetValue($Target, [ref]$memoized)) {
        return $memoized
    }

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
            if (Get-Command "Write-CCFLogWarn" -ErrorAction SilentlyContinue) {
                Write-CCFLogWarn "Override de ruta bloqueado por seguridad (Fuera de scope): $override"
            }
            $override = $null
        }
        else { return $targetPath }
    }

    $finalPath = switch ($Target) {
        "Root" { $script:ArgosCCFRoot }
        "Core" { Join-Path $script:ArgosCCFRoot "Core" }
        "Configs" { Join-Path $script:ArgosCCFRoot "Configs" }
        "Logs" { Join-Path $script:ArgosCCFRoot "Logs" }
        "Tests" { Join-Path $script:ArgosCCFRoot "Tests" }
        "Plugins" { Join-Path $script:ArgosCCFRoot "Plugins" }
    }

    # Guardar en Cache
    $null = $script:PathCache.TryAdd($Target, $finalPath)
    return $finalPath
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
    'Initialize-CCFLogger',
    'Write-CCFLog',
    'Write-CCFLogInfo',
    'Write-CCFLogSuccess',
    'Write-CCFLogWarn',
    'Write-CCFLogError',
    'Write-CCFLogCritical',
    'Write-CCFLogDebug',
    'Write-CCFLogHeader',
    'Write-CCFSecurityRecord',
    'Write-CCFAuditRecord',
    'Write-CCFErrorRecord',
    'Get-CCFConfig',
    'Set-CCFUserConfig',
    'Remove-CCFConfigCache',
    'Test-CCFConfigSchema',
    'Get-CCFPlugins',
    'Invoke-CCFPlugin',
    'Confirm-CCFPluginSignature',
    'Invoke-CCFParallel',
    'Test-CCFHealth',
    'Submit-CCFHeartbeat',
    'Initialize-CCFEnvironment',
    'Protect-CCFSensitiveData',
    'Test-CCFEntropyContent'
) -Alias @(
    'Log-Info', 'Log-Success', 'Log-Warn', 'Log-Error', 'Log-Critical', 'Log-Debug', 'Log-Header',
    'Init-CCFLogger', 'Catch-CCFError', 'Log-Attack', 'Log-Audit', 'Redact-CCFSensitiveData',
    'Clear-CCFConfigCache', 'Test-CCFPluginSignature', 'Test-CCFHighEntropy'
)
