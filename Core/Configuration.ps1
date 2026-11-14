# ArgosCCF configuration manager.
#
# Layered JSON configuration: Configs/Factory/<name>.json, then optional presets from
# Configs/Presets/<preset>.json, then the user's overrides in Configs/User/<name>.json, merged
# in that order and cached in memory.

$script:ConfigCache = [System.Collections.Concurrent.ConcurrentDictionary[string, object]]::new()

function Test-CCFConfigName {
    <#
    .SYNOPSIS
        True when a configuration or preset name is a plain file name, not a path.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowEmptyString()][string]$Name)

    return ($Name -match '^[A-Za-z0-9][A-Za-z0-9._-]*$' -and $Name -notmatch '\.\.')
}

function Read-CCFJsonFile {
    <#
    .SYNOPSIS
        Reads a JSON file as UTF-8 (Windows PowerShell 5.1 would read it as ANSI otherwise).
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param([Parameter(Mandatory = $true)][string]$Path)

    return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Merge-CCFConfig {
    <#
    .SYNOPSIS
        Merges one configuration object into another, recursively.

    .DESCRIPTION
        Copies every property of -Override into -Base and returns -Base. Nested objects are
        merged property by property, arrays are concatenated, and any other value in -Override
        replaces the one in -Base. -Base is modified in place; pass a copy if you need to keep
        the original. Get-CCFConfig uses it to apply presets and user settings.

    .PARAMETER Base
        The object to merge into. It is modified.

    .PARAMETER Override
        The object whose values take precedence.

    .EXAMPLE
        $base = '{"Logging":{"Level":"INFO","Path":"Logs"}}' | ConvertFrom-Json
        $over = '{"Logging":{"Level":"DEBUG"}}' | ConvertFrom-Json
        (Merge-CCFConfig -Base $base -Override $over).Logging

        Returns Level = DEBUG and Path = Logs.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
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
                $null = Merge-CCFConfig -Base $baseVal -Override $overVal
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

function Get-CCFConfig {
    <#
    .SYNOPSIS
        Loads a configuration by name, merging the factory, preset and user layers.

    .DESCRIPTION
        Reads Configs/Factory/<ConfigName>.json, merges the section named <ConfigName> of each
        preset in Configs/Presets/<preset>.json, then merges Configs/User/<ConfigName>.json, and
        returns the result. The result is cached per name and preset list; use -ForceRefresh
        or Remove-CCFConfigCache after changing the files. Names must be plain file names:
        anything that looks like a path is refused and logged as a security block.
        The returned object is the cached one, so changes to it are visible to later calls.

    .PARAMETER ConfigName
        Name of the configuration, without .json. Letters, digits, '.', '-' and '_'.

    .PARAMETER ActivePresets
        Presets to apply, in order, between the factory and the user layers.

    .PARAMETER ForceRefresh
        Read the files again instead of returning the cached result.

    .EXAMPLE
        (Get-CCFConfig -ConfigName 'ccf_core').Logging

        Returns the logging section of the core configuration.

    .EXAMPLE
        Get-CCFConfig -ConfigName 'demo_app' -ActivePresets 'Production' -ForceRefresh

        Reloads demo_app with the Production preset applied.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigName,

        [string[]]$ActivePresets = @(),

        [switch]$ForceRefresh
    )

    # Security: names become file names, so refuse anything that could leave Configs.
    foreach ($name in @($ConfigName) + $ActivePresets) {
        if (-not (Test-CCFConfigName -Name $name)) {
            Write-CCFLogError "BLOQUEO DE SEGURIDAD: Intento de Path Traversal o nombre de configuración inválido: $name"
            return $null
        }
    }

    $cacheKey = $ConfigName + '|' + ($ActivePresets -join ',')
    $cachedVal = $null
    if (-not $ForceRefresh -and $script:ConfigCache.TryGetValue($cacheKey, [ref]$cachedVal)) {
        Write-CCFLogDebug "Retornando configuración desde caché para: $ConfigName"
        return $cachedVal
    }

    $configRoot = Get-CCFPath -Target 'Configs'
    $factoryPath = Join-Path (Join-Path $configRoot 'Factory') "$ConfigName.json"
    $presetsPath = Join-Path $configRoot 'Presets'
    $userPath = Join-Path (Join-Path $configRoot 'User') "$ConfigName.json"

    $finalConfig = [PSCustomObject]@{}

    if (Test-Path -LiteralPath $factoryPath) {
        try {
            $finalConfig = Read-CCFJsonFile -Path $factoryPath
            Write-CCFLogDebug "Base cargada para: $ConfigName"
        }
        catch {
            Write-CCFLogError "Fallo crítico al cargar Factory Config ${ConfigName}: $($_.Exception.Message)"
            return $null
        }
    }

    foreach ($preset in $ActivePresets) {
        $pPath = Join-Path $presetsPath "$preset.json"
        if (Test-Path -LiteralPath $pPath) {
            try {
                $pContent = Read-CCFJsonFile -Path $pPath
                if ($pContent.PSObject.Properties[$ConfigName]) {
                    $finalConfig = Merge-CCFConfig -Base $finalConfig -Override $pContent.$ConfigName
                }
            }
            catch { Write-CCFLogWarn "Fallo al aplicar preset '$preset'" }
        }
    }

    if (Test-Path -LiteralPath $userPath) {
        try {
            $finalConfig = Merge-CCFConfig -Base $finalConfig -Override (Read-CCFJsonFile -Path $userPath)
        }
        catch { Write-CCFLogWarn "Fallo al cargar User Config para $ConfigName" }
    }

    $script:ConfigCache[$cacheKey] = $finalConfig
    return $finalConfig
}

function Set-CCFUserConfig {
    <#
    .SYNOPSIS
        Saves user settings for a configuration and clears its cached copies.

    .DESCRIPTION
        Writes -ConfigObject as JSON (UTF-8) to Configs/User/<ConfigName>.json, the top layer
        that Get-CCFConfig merges over the factory and preset layers. Cached results for that
        name are removed, so the next Get-CCFConfig reads the new values.
        Names must be plain file names; anything that looks like a path is refused.
        Supports -WhatIf and -Confirm.

    .PARAMETER ConfigName
        Name of the configuration, without .json. Letters, digits, '.', '-' and '_'.

    .PARAMETER ConfigObject
        The settings to save. Usually only the values that differ from the factory file.

    .EXAMPLE
        Set-CCFUserConfig -ConfigName 'ccf_core' -ConfigObject ([pscustomobject]@{ Security = @{ RequireSignedPlugins = $true } })

        Requires signed plugins for this installation.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigName,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ConfigObject
    )

    if (-not (Test-CCFConfigName -Name $ConfigName)) {
        Write-CCFLogError "BLOQUEO DE SEGURIDAD: Intento de Path Traversal o nombre de configuración inválido: $ConfigName"
        return
    }

    $userDir = Join-Path (Get-CCFPath -Target 'Configs') 'User'
    $userPath = Join-Path $userDir "$ConfigName.json"
    if (-not $PSCmdlet.ShouldProcess($userPath, 'Save user configuration')) { return }

    try {
        if (-not (Test-Path -LiteralPath $userDir)) { New-Item -ItemType Directory -Path $userDir -Force | Out-Null }
        $ConfigObject | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $userPath -Encoding UTF8 -Force -ErrorAction Stop
        Write-CCFLogSuccess "Configuración guardada en ${userPath}"

        foreach ($key in @($script:ConfigCache.Keys | Where-Object { $_.StartsWith("$ConfigName|") })) {
            $removed = $null
            $null = $script:ConfigCache.TryRemove($key, [ref]$removed)
        }
        Write-CCFLogDebug "Caché invalidada para: $ConfigName"
    }
    catch {
        Write-CCFLogError "No se pudo guardar en ${userPath}: $($_.Exception.Message)"
    }
}

function Remove-CCFConfigCache {
    <#
    .SYNOPSIS
        Clears the in-memory configuration cache.

    .DESCRIPTION
        Removes every cached result of Get-CCFConfig, so the next call reads the JSON files
        again. Use it after editing configuration files outside Set-CCFUserConfig. The files
        are not touched. The alias Clear-CCFConfigCache is kept for older scripts.

    .EXAMPLE
        Remove-CCFConfigCache

        Clears the cache.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Clears an in-memory cache only; no files are changed.')]
    [CmdletBinding()]
    param()

    $script:ConfigCache.Clear()
    Write-CCFLogInfo 'Caché de configuración vaciada.'
}

function Test-CCFConfigSchema {
    <#
    .SYNOPSIS
        Validates a configuration object against a simple schema and fills in defaults.

    .DESCRIPTION
        The schema is a hashtable with one entry per property. Each entry is a hashtable that
        can contain Mandatory ($true/$false), Type (a .NET type such as [int]), AllowedValues
        (an array) and Default. Missing properties with a Default are added to -Config.
        Returns $true when the configuration is valid; otherwise logs each problem at ERROR
        level and returns $false.

    .PARAMETER Config
        The configuration object to check. Defaults are added to it.

    .PARAMETER Schema
        Hashtable describing the expected properties.

    .EXAMPLE
        $schema = @{
            Port = @{ Mandatory = $true; Type = [int] }
            Mode = @{ AllowedValues = 'Audit', 'Enforce'; Default = 'Audit' }
        }
        Test-CCFConfigSchema -Config ([pscustomobject]@{ Port = 8080 }) -Schema $schema

        Returns $true and adds Mode = Audit to the object.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config,

        [Parameter(Mandatory = $true)]
        [hashtable]$Schema
    )

    $errors = [System.Collections.Generic.List[string]]::new()

    foreach ($key in $Schema.Keys) {
        $rule = $Schema[$key]
        $val = $Config.$key

        if ($rule.Mandatory -and ($null -eq $val)) {
            $errors.Add("Campo obligatorio faltante: $key")
            continue
        }

        if ($null -eq $val) {
            if ($null -ne $rule.Default) {
                $Config | Add-Member -NotePropertyName $key -NotePropertyValue $rule.Default -Force
                Write-CCFLogDebug "Aplicado valor por defecto para $($key): $($rule.Default)"
            }
            continue
        }

        if ($null -ne $rule.Type -and -not ($val -is $rule.Type)) {
            $errors.Add("Tipo incorrecto para $key. Esperado: $($rule.Type.Name), Obtenido: $($val.GetType().Name)")
        }

        if ($null -ne $rule.AllowedValues -and @($rule.AllowedValues) -notcontains $val) {
            $errors.Add("Valor '$val' no permitido para $key. Opciones: $(@($rule.AllowedValues) -join ', ')")
        }
    }

    if ($errors.Count -gt 0) {
        foreach ($err in $errors) { Write-CCFLogError "Validación de Config: $err" }
        return $false
    }
    return $true
}

# Name from earlier versions, kept so existing scripts keep working.
New-Alias -Name Clear-CCFConfigCache -Value Remove-CCFConfigCache
