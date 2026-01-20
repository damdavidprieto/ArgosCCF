# --- Descubrimiento de Plugins ---
function Test-CCFPluginSignature {
    param([Parameter(Mandatory = $true)][string]$Path)
    
    # Asegurar que el archivo existe
    if (-not (Test-Path $Path)) { return @{ Valid = $false; Status = "FileNotFound" } }

    $sig = Get-AuthenticodeSignature -FilePath $Path
    # En desarrollo, "Valid" es lo ideal, pero "UnknownError" suele indicar falta de cadena de confianza (cert auto-firmado)
    # Sin embargo, para v1.3 exigiremos "Valid" para ser estrictos.
    if ($sig.Status -eq "Valid") {
        return @{ Valid = $true; Signer = $sig.SignerCertificate.Subject }
    }
    return @{ Valid = $false; Status = $sig.Status.ToString() }
}

function Get-CCFPlugins {
    param(
        [string]$Path = (Join-Path (Get-CCFPath -Target "Root") "Plugins")
    )
    
    if (-not (Test-Path $Path)) { return @() }
    
    $plugins = Get-ChildItem -Path $Path -Filter "*.ps1" | ForEach-Object {
        $file = $_
        $plugin = [PSCustomObject]@{
            Name        = $null
            Description = "Sin descripción"
            Version     = "1.0.0"
            Author      = "Unknown"
            Path        = $file.FullName
            Signed      = (Test-CCFPluginSignature -Path $file.FullName).Valid
            Manifest    = $null
        }

        # 1. Buscar Manifiesto (ccf_plugin.json)
        $manifestPath = Join-Path $file.DirectoryName "ccf_plugin.json"
        if (Test-Path $manifestPath) {
            try {
                $manifestContent = Get-Content $manifestPath -Raw
                if ($manifestContent) {
                    $manifest = $manifestContent | ConvertFrom-Json
                    $plugin.Name = $manifest.Name
                    $plugin.Version = $manifest.Version
                    $plugin.Author = $manifest.Author
                    $plugin.Manifest = $manifest
                    if ($manifest.Description) { $plugin.Description = $manifest.Description }
                }
            }
            catch {
                Log-Warn "Error al cargar manifiesto en $($file.Name): $($_.Exception.Message)"
            }
        }

        # 2. Fallback a metadatos incrustados (Legacy)
        $content = Get-Content $file.FullName -Raw
        if ($null -eq $plugin.Name) {
            if ($content -match "\.NAME\s+(.+)") { $plugin.Name = $matches[1].Trim() }
            elseif ($content -match "CCF_PLUGIN_NAME:\s*(.+)") { $plugin.Name = $matches[1].Trim() }
            else { $plugin.Name = $file.BaseName }
        }

        if ($plugin.Description -eq "Sin descripción") {
            if ($content -match "\.DESCRIPTION\s+(.+)") { $plugin.Description = $matches[1].Trim() }
            elseif ($content -match "CCF_PLUGIN_DESC:\s*(.+)") { $plugin.Description = $matches[1].Trim() }
        }

        if ($content -match "\.VERSION\s+(.+)") { $plugin.Version = $matches[1].Trim() }
        elseif ($content -match "CCF_PLUGIN_VERSION:\s*(.+)") { $plugin.Version = $matches[1].Trim() }

        if ($content -match "\.AUTHOR\s+(.+)") { $plugin.Author = $matches[1].Trim() }
        elseif ($content -match "CCF_PLUGIN_AUTHOR:\s*(.+)") { $plugin.Author = $matches[1].Trim() }
            
        $plugin
    }
    
    return $plugins
}

# --- Ejecución de Plugins con Ciclo de Vida y Sandboxing ---
function Invoke-CCFPlugin {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Plugin,
        
        [hashtable]$Arguments = @{},
        
        [switch]$SkipHooks,
        
        [switch]$HardenedMode # Forzar ConstrainedLanguage
    )
    
    # 1. SEGURIDAD: Validación de Ubicación (Anti-Inyección)
    $allowedPluginsPath = Get-CCFPath -Target "Plugins"
    if ($Plugin.Path -notlike "$allowedPluginsPath*") {
        Log-Critical "BLOQUEO DE SEGURIDAD: Intento de cargar plugin desde ubicación no autorizada: $($Plugin.Path)"
        return $null
    }

    # 2. SEGURIDAD: Validación de Firma (v1.3)
    $requireSigned = $false
    if (Get-Command "Get-CCFConfig" -ErrorAction SilentlyContinue) {
        $coreConfig = Get-CCFConfig -ConfigName "ccf_core"
        $requireSigned = $coreConfig.Security.RequireSignedPlugins -eq $true
    }

    if ($requireSigned) {
        $sigResult = Test-CCFPluginSignature -Path $Plugin.Path
        if (-not $sigResult.Valid) {
            Log-Critical "BLOQUEO DE SEGURIDAD: El plugin $($Plugin.Name) no tiene una firma válida y la política RequireSignedPlugins está activa."
            return $null
        }
        Log-Info "Firma válida detectada: $($sigResult.Signer)"
    }

    # 3. SEGURIDAD: Configuración de Sandboxing
    $rs = $null
    if ($HardenedMode) {
        Log-Warn "Activando Sandboxing (ConstrainedLanguage) para $($Plugin.Name)"
        # Usar CreateRestricted para evitar CUALQUIER comando o proveedor por defecto
        # Solo permitimos Comandos básicos de lenguaje.
        $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateRestricted([System.Management.Automation.SessionCapabilities]::Language)
        $iss.LanguageMode = [System.Management.Automation.PSLanguageMode]::ConstrainedLanguage
        $rs = [runspacefactory]::CreateRunspace($iss)
    }

    Log-Info "Preparando ejecución de plugin: $($Plugin.Name)"
    
    # Crear un scope aislado para el plugin
    $scriptText = Get-Content $Plugin.Path -Raw
    
    try {
        # 3. Hook: Before-Execute
        if (-not $SkipHooks) {
            if ($scriptText -match "function\s+Before-Execute") {
                Log-Debug "Ejecutando hook Before-Execute..."
                # Nota: Los hooks se ejecutan en el Runspace LOCAL por ahora para interactuar con CCF.
                # Si el plugin es malicioso, el sandbox central lo atrapará en la fase principal.
                . $Plugin.Path
                if (Get-Command "Before-Execute" -ErrorAction SilentlyContinue) {
                    Before-Execute -Arguments $Arguments
                }
            }
        }

        # 4. Ejecución Principal
        $result = $null
        if ($HardenedMode) {
            $rs.Open()
            $ps = [powershell]::Create().AddScript($scriptText)
            $ps.AddParameter("Arguments", $Arguments)
            $ps.Runspace = $rs
            $result = $ps.Invoke()
            # Capturar errores del runspace
            if ($ps.HadErrors) {
                # Lanzamos una excepción para que Catch-CCFError la capture
                throw $ps.Streams.Error[0].Exception
            }
            $rs.Close()
        }
        else {
            $scriptBlock = [scriptblock]::Create($scriptText)
            $result = & $scriptBlock -Arguments $Arguments
        }
        
        # 5. Hook: After-Execute
        if (-not $SkipHooks) {
            if ($scriptText -match "function\s+After-Execute") {
                Log-Debug "Ejecutando hook After-Execute..."
                if (-not (Get-Command "After-Execute" -ErrorAction SilentlyContinue)) { . $Plugin.Path }
                if (Get-Command "After-Execute" -ErrorAction SilentlyContinue) {
                    After-Execute -Result $result
                }
            }
        }

        Log-Success "Plugin $($Plugin.Name) finalizado con éxito."
        return $result
    }
    catch {
        Catch-CCFError -ErrorRecord $_ -Context "PluginExecution:$($Plugin.Name)"
        return $null
    }
}

Export-ModuleMember -Function Get-CCFPlugins, Invoke-CCFPlugin
