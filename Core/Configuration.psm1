<#
    .SYNOPSIS
    CCF Configuration Manager - Deep Merge & Layered (Optimized)
    
    .DESCRIPTION
    Gestiona la configuración del framework y aplicaciones basadas en CCF.
    Incluye un sistema de caché en memoria para alto rendimiento.
#>

$script:ConfigCache = @{}

# --- Auxiliar: Fusión Recursiva (Deep Merge) ---
function Merge-CCFConfig {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Base,
        
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Override
    )
    
    foreach ($prop in $Override.PSObject.Properties) {
        if ($null -eq $Base.PSObject.Properties[$prop.Name]) {
            $Base | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $prop.Value -Force
        }
        else {
            $baseVal = $Base.($prop.Name)
            $overVal = $prop.Value
            
            if ($baseVal -is [PSCustomObject] -and $overVal -is [PSCustomObject]) {
                Merge-CCFConfig -Base $baseVal -Override $overVal
            }
            elseif ($baseVal -is [array] -and $overVal -is [array]) {
                $Base.($prop.Name) = $baseVal + $overVal
            }
            else {
                $Base.($prop.Name) = $overVal
            }
        }
    }
    return $Base
}

# --- Carga de Configuración con Caché ---
function Get-CCFConfig {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigName,
        
        [string[]]$ActivePresets = @(),
        
        [switch]$ForceRefresh
    )
    
    # 1. Verificar Caché (Si no hay ForceRefresh)
    $cacheKey = "$ConfigName" + ($ActivePresets -join ",")
    if ($script:ConfigCache.ContainsKey($cacheKey) -and -not $ForceRefresh) {
        Log-Debug "Retornando configuración desde caché para: $ConfigName"
        return $script:ConfigCache[$cacheKey]
    }

    $configRoot = Get-CCFPath -Target "Configs"
    $factoryPath = Join-Path $configRoot "Factory\$ConfigName.json"
    $presetsPath = Join-Path $configRoot "Presets"
    $userPath = Join-Path $configRoot "User\$ConfigName.json"
    
    $finalConfig = [PSCustomObject]@{}
    
    # 1. Cargar Factory
    if (Test-Path $factoryPath) {
        try {
            $finalConfig = Get-Content $factoryPath -Raw | ConvertFrom-Json
            Log-Debug "Base cargada para: $ConfigName"
        }
        catch {
            Log-Error "Fallo crítico al cargar Factory Config ${ConfigName}: $($_.Exception.Message)"
            return $null
        }
    }
    
    # 2. Cargar Presets
    foreach ($preset in $ActivePresets) {
        $pPath = Join-Path $presetsPath "$preset.json"
        if (Test-Path $pPath) {
            try {
                $pContent = Get-Content $pPath -Raw | ConvertFrom-Json
                if ($pContent.PSObject.Properties[$ConfigName]) {
                    $finalConfig = Merge-CCFConfig -Base $finalConfig -Override $pContent.$ConfigName
                }
            }
            catch { Log-Warn "Fallo al aplicar preset '$preset'" }
        }
    }
    
    # 3. Cargar User
    if (Test-Path $userPath) {
        try {
            $uContent = Get-Content $userPath -Raw | ConvertFrom-Json
            $finalConfig = Merge-CCFConfig -Base $finalConfig -Override $uContent
        }
        catch { Log-Warn "Fallo al cargar User Config para $ConfigName" }
    }
    
    # Guardar en Caché
    $script:ConfigCache[$cacheKey] = $finalConfig
    return $finalConfig
}

# --- Guardado e Invalidación de Caché ---
function Set-CCFUserConfig {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigName,
        
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ConfigObject
    )
    
    $userDir = Join-Path (Get-CCFPath -Target "Configs") "User"
    if (-not (Test-Path $userDir)) { New-Item -ItemType Directory -Path $userDir -Force | Out-Null }
    
    $userPath = Join-Path $userDir "$ConfigName.json"
    
    try {
        $ConfigObject | ConvertTo-Json -Depth 10 | Set-Content $userPath -Force
        Log-Success "Configuración guardada en ${userPath}"
        
        # Invalidar todas las entradas de caché para este ConfigName
        $keysToClear = $script:ConfigCache.Keys | Where-Object { $_ -like "$ConfigName*" }
        foreach ($k in $keysToClear) { $script:ConfigCache.Remove($k) }
        Log-Debug "Caché invalidada para: $ConfigName"
    }
    catch {
        Log-Error "No se pudo guardar en $userPath"
    }
}

# --- Limpieza de Caché ---
function Clear-CCFConfigCache {
    $script:ConfigCache.Clear()
    Log-Info "Caché de configuración vaciada."
}

# --- Validación de Esquiva (Schema-lite) ---
function Test-CCFConfigSchema {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Schema
    )
    
    $errors = New-Object System.Collections.Generic.List[string]
    
    foreach ($key in $Schema.Keys) {
        $expectedType = $Schema[$key]
        $val = $Config.$key
        
        if ($null -eq $val) {
            $errors.Add("Campo faltante: $key")
        }
        elseif (-not ($val -is $expectedType)) {
            $errors.Add("Tipo incorrecto para $key. Esperado: $($expectedType.Name), Obtenido: $($val.GetType().Name)")
        }
    }
    
    if ($errors.Count -gt 0) {
        foreach ($err in $errors) { Log-Error "Validación de Config: $err" }
        return $false
    }
    return $true
}

Export-ModuleMember -Function Get-CCFConfig, Set-CCFUserConfig, Clear-CCFConfigCache, Test-CCFConfigSchema
