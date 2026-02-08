<#
    .SYNOPSIS
    CCF Configuration Manager - Deep Merge & Layered (Optimized)
    
    .DESCRIPTION
    Gestiona la configuración del framework y aplicaciones basadas en CCF.
    Incluye un sistema de caché en memoria para alto rendimiento.
#>

$script:ConfigCache = New-Object -TypeName 'System.Collections.Concurrent.ConcurrentDictionary[string,object]'

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
    $cachedVal = $null
    if (-not $ForceRefresh -and $script:ConfigCache.TryGetValue($cacheKey, [ref]$cachedVal)) {
        Write-CCFLogDebug "Retornando configuración desde caché para: $ConfigName"
        return $cachedVal
    }

    # SEGURIDAD: Sanitización de ConfigName (Anti-PathTraversal)
    if ($ConfigName -match "[\\/:]" -or $ConfigName -match "\.\.") {
        Log-Error "BLOQUEO DE SEGURIDAD: Intento de Path Traversal o nombre de configuración inválido: $ConfigName"
        return $null
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
    $null = $script:ConfigCache.TryAdd($cacheKey, $finalConfig)
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
        foreach ($k in $keysToClear) { 
            $removed = $null
            $null = $script:ConfigCache.TryRemove($k, [ref]$removed) 
        }
        Write-CCFLogDebug "Caché invalidada para: $ConfigName"
    }
    catch {
        Log-Error "No se pudo guardar en $userPath"
    }
}

# --- Limpieza de Caché ---
function Remove-CCFConfigCache {
    $script:ConfigCache.Clear()
    Write-CCFLogInfo "Caché de configuración vaciada."
}

# --- Validación de Esquiva (Schema Professional API) ---
function Test-CCFConfigSchema {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Schema
    )
    
    $errors = New-Object System.Collections.Generic.List[string]
    
    foreach ($key in $Schema.Keys) {
        $rule = $Schema[$key]
        $val = $Config.$key
        
        # 1. Check Mandatory
        if ($rule.Mandatory -and ($null -eq $val)) {
            $errors.Add("Campo obligatorio faltante: $key")
            continue
        }

        if ($null -eq $val) {
            # Apply Default if available
            if ($null -ne $rule.Default) {
                $Config | Add-Member -NotePropertyName $key -NotePropertyValue $rule.Default -Force
                Log-Debug "Aplicado valor por defecto para $($key): $($rule.Default)"
            }
            continue
        }
        
        # 2. Check Type
        if ($null -ne $rule.Type) {
            if (-not ($val -is $rule.Type)) {
                $errors.Add("Tipo incorrecto para $key. Esperado: $($rule.Type.Name), Obtenido: $($val.GetType().Name)")
            }
        }

        # 3. Check Allowed Values
        if ($null -ne $rule.AllowedValues -and ($rule.AllowedValues -is [array])) {
            if ($rule.AllowedValues -notcontains $val) {
                $errors.Add("Valor '$val' no permitido para $key. Opciones: $($rule.AllowedValues -join ', ')")
            }
        }
    }
    
    if ($errors.Count -gt 0) {
        foreach ($err in $errors) { Log-Error "Validación de Config: $err" }
        return $false
    }
    return $true
}

# --- Alias de Retrocompatibilidad ---
New-Alias -Name Clear-CCFConfigCache -Value Remove-CCFConfigCache

Export-ModuleMember -Function Get-CCFConfig, Set-CCFUserConfig, Remove-CCFConfigCache, Test-CCFConfigSchema -Alias *
