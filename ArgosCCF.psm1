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
$script:ArgosCCFRoot = (Get-Item $PSScriptRoot).FullName
$script:PathCache = New-Object -TypeName 'System.Collections.Concurrent.ConcurrentDictionary[string,string]'

function Initialize-CCFEnvironment {
    [CmdletBinding()]
    param()

    # 1. Descubrimiento Inteligente de Raíz
    if (Test-Path (Join-Path $script:ArgosCCFRoot "Core")) {
        # Already correct
    }
    elseif ($env:ARGOS_CCF_ROOT -and (Test-Path $env:ARGOS_CCF_ROOT)) {
        $script:ArgosCCFRoot = $env:ARGOS_CCF_ROOT
    }

    # 2. Estructura: Configs y Plugins vienen con el módulo; se crean solo si faltan.
    foreach ($p in "Configs", "Plugins") {
        $path = Join-Path $script:ArgosCCFRoot $p
        if (-not (Test-Path $path)) {
            try { New-Item -ItemType Directory -Path $path -Force -ErrorAction Stop | Out-Null }
            catch { Write-Verbose "No se pudo crear ${path}: $($_.Exception.Message)" }
        }
    }

    # 3. Logs: junto al módulo si se puede escribir ahí; si no (por ejemplo, instalado
    #    para todos los usuarios en Program Files), en una carpeta del usuario.
    $script:LogsPath = Join-Path $script:ArgosCCFRoot "Logs"
    if (-not (Test-CCFWritableDirectory -Path $script:LogsPath)) {
        $userData = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA }
        elseif ($env:XDG_DATA_HOME) { $env:XDG_DATA_HOME }
        else { Join-Path $HOME ".local/share" }
        $script:LogsPath = Join-Path (Join-Path $userData "ArgosCCF") "Logs"
        if (-not (Test-CCFWritableDirectory -Path $script:LogsPath)) {
            Write-Warning "ArgosCCF: no hay ninguna carpeta de logs con permiso de escritura; los logs solo se mostrarán en consola."
        }
    }
    $null = $script:PathCache.TryRemove("Logs", [ref]$null)
}

function Test-CCFWritableDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null }
        $probe = Join-Path $Path ".ccf_write_test"
        "test" | Out-File $probe -ErrorAction Stop
        Remove-Item $probe -ErrorAction SilentlyContinue
        return $true
    }
    catch {
        return $false
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
        "Logs" { $script:LogsPath }
        "Tests" { Join-Path $script:ArgosCCFRoot "Tests" }
        "Plugins" { Join-Path $script:ArgosCCFRoot "Plugins" }
    }

    # Guardar en Cache
    $script:PathCache.TryAdd($Target, $finalPath) | Out-Null
    return $finalPath
}

# --- Core ---
# The Core files are dot-sourced into this module's scope, so their functions can call
# each other and are exported only through the list below (and the manifest).
$corePath = Join-Path $PSScriptRoot "Core"
foreach ($coreFile in "Logging.ps1", "Configuration.ps1", "Plugins.ps1", "Execution.ps1") {
    . (Join-Path $corePath $coreFile)
}

# Keep in sync with FunctionsToExport / AliasesToExport in ArgosCCF.psd1
# (Tests/Unit/Manifest.Tests.ps1 checks it).
Export-ModuleMember -Function @(
    'Get-CCFPath',
    'Initialize-CCFEnvironment',
    'Set-CCFLogLevel',
    'Register-CCFLogProvider',
    'Register-CCFSIEMProvider',
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
    'Remove-CCFOldLog',
    'Protect-CCFSensitiveData',
    'Test-CCFEntropyContent',
    'Test-CCFHealth',
    'Submit-CCFHeartbeat',
    'Get-CCFConfig',
    'Set-CCFUserConfig',
    'Merge-CCFConfig',
    'Remove-CCFConfigCache',
    'Test-CCFConfigSchema',
    'Get-CCFPlugins',
    'Invoke-CCFPlugin',
    'Confirm-CCFPluginSignature',
    'Invoke-CCFParallel'
) -Alias @(
    'Log-Info', 'Log-Success', 'Log-Warn', 'Log-Error', 'Log-Critical', 'Log-Debug', 'Log-Header',
    'Log-Attack', 'Log-Audit', 'Init-CCFLogger', 'Catch-CCFError', 'Redact-CCFSensitiveData',
    'Test-CCFHighEntropy', 'Remove-OldCCFLogs', 'Clear-CCFConfigCache', 'Test-CCFPluginSignature'
)
