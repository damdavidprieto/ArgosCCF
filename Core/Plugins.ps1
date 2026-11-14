# --- Descubrimiento de Plugins ---
function Confirm-CCFPluginSignature {
    param([Parameter(Mandatory = $true)][string]$Path)
    
    # Asegurar que el archivo existe
    if (-not (Test-Path $Path)) { return @{ Valid = $false; Status = "FileNotFound" } }

    # Authenticode solo existe en Windows. En Linux/macOS no se puede verificar la firma,
    # asi que se falla de forma segura: el plugin se considera NO firmado (no valido).
    if (-not (Get-Command "Get-AuthenticodeSignature" -ErrorAction SilentlyContinue)) {
        return @{ Valid = $false; Status = "NotSupportedOnPlatform" }
    }

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
            Signed      = (Confirm-CCFPluginSignature -Path $file.FullName).Valid
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

# --- Helpers de seguridad (privados) ---
function Test-CCFPluginLocation {
    # True only when Path resolves to a .ps1 file inside the Plugins folder. Paths are
    # normalized first, so "Plugins\..\x.ps1" and sibling folders like "PluginsX" are rejected.
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try {
        $root = [System.IO.Path]::GetFullPath((Get-CCFPath -Target "Plugins")).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
        $full = [System.IO.Path]::GetFullPath($Path)
    }
    catch { return $false }

    $comparison = if ($IsLinux -or $IsMacOS) { [StringComparison]::Ordinal } else { [StringComparison]::OrdinalIgnoreCase }
    if (-not $full.StartsWith($root, $comparison)) { return $false }
    if ([System.IO.Path]::GetExtension($full) -ne ".ps1") { return $false }
    return (Test-Path -LiteralPath $full -PathType Leaf)
}

function Invoke-CCFPluginCode {
    # Runs plugin code. With -Hardened it runs in a new restricted runspace in
    # ConstrainedLanguage mode; otherwise in the caller's session.
    param(
        [Parameter(Mandatory = $true)][string]$ScriptText,
        [hashtable]$Parameters = @{},
        [switch]$Hardened
    )

    if (-not $Hardened) {
        $scriptBlock = [scriptblock]::Create($ScriptText)
        return (& $scriptBlock @Parameters)
    }

    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateRestricted([System.Management.Automation.SessionCapabilities]::Language)
    $iss.LanguageMode = [System.Management.Automation.PSLanguageMode]::ConstrainedLanguage
    $rs = [runspacefactory]::CreateRunspace($iss)
    $ps = $null
    try {
        $rs.Open()
        $ps = [powershell]::Create().AddScript($ScriptText)
        foreach ($key in $Parameters.Keys) { $null = $ps.AddParameter($key, $Parameters[$key]) }
        $ps.Runspace = $rs
        $result = $ps.Invoke()
        if ($ps.HadErrors) { throw $ps.Streams.Error[0].Exception }
    }
    finally {
        if ($ps) { $ps.Dispose() }
        $rs.Dispose()
    }

    # Invoke returns a collection; flatten it for consistency with the unrestricted path.
    if ($result.Count -eq 0) { return $null }
    if ($result.Count -eq 1) { return $result[0] }
    return $result
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
    if (-not (Test-CCFPluginLocation -Path $Plugin.Path)) {
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
        $sigResult = Confirm-CCFPluginSignature -Path $Plugin.Path
        if (-not $sigResult.Valid) {
            Log-Critical "BLOQUEO DE SEGURIDAD: El plugin $($Plugin.Name) no tiene una firma válida y la política RequireSignedPlugins está activa."
            return $null
        }
        Log-Info "Firma válida detectada: $($sigResult.Signer)"
    }

    if ($HardenedMode) {
        Log-Warn "Activando Sandboxing (ConstrainedLanguage) para $($Plugin.Name)"
    }

    Log-Info "Preparando ejecución de plugin: $($Plugin.Name)"

    $scriptText = Get-Content -LiteralPath $Plugin.Path -Raw

    # Hooks are read from the plugin's AST instead of dot-sourcing the file, so defining
    # them does not run the plugin's main code a second time. Only the hook body's text is
    # kept: in HardenedMode it runs in the same restricted runspace as the plugin.
    $hooks = @{}
    if (-not $SkipHooks) {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($scriptText, [ref]$null, [ref]$null)
        foreach ($name in "Before-Execute", "After-Execute") {
            $fn = $ast.Find({
                    param($node)
                    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
                }, $false)
            if ($fn) {
                $body = $fn.Body.Extent.Text.Trim()
                $hooks[$name] = $body.Substring(1, $body.Length - 2)
            }
        }
    }

    try {
        # 3. Hook: Before-Execute
        if ($hooks["Before-Execute"]) {
            Log-Debug "Ejecutando hook Before-Execute..."
            $null = Invoke-CCFPluginCode -ScriptText $hooks["Before-Execute"] -Parameters @{ Arguments = $Arguments } -Hardened:$HardenedMode
        }

        # 4. Ejecución Principal
        $result = Invoke-CCFPluginCode -ScriptText $scriptText -Parameters @{ Arguments = $Arguments } -Hardened:$HardenedMode

        # 5. Hook: After-Execute
        if ($hooks["After-Execute"]) {
            Log-Debug "Ejecutando hook After-Execute..."
            $null = Invoke-CCFPluginCode -ScriptText $hooks["After-Execute"] -Parameters @{ Result = $result } -Hardened:$HardenedMode
        }

        Log-Success "Plugin $($Plugin.Name) finalizado con éxito."
        return $result
    }
    catch {
        Write-CCFErrorRecord -ErrorRecord $_ -Context "PluginExecution:$($Plugin.Name)"
        return $null
    }
}

# --- Alias de Retrocompatibilidad ---
New-Alias -Name Test-CCFPluginSignature -Value Confirm-CCFPluginSignature

