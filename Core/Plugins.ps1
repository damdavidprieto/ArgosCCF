# ArgosCCF plugins.
#
# Discovery (Get-CCFPlugin), signature checks (Confirm-CCFPluginSignature) and execution with
# lifecycle hooks and an optional restricted runspace (Invoke-CCFPlugin).

# --- Private helpers ---

function Read-CCFPluginFile {
    <#
    .SYNOPSIS
        Reads a plugin once and returns its bytes and text, so the code that is checked is the code that runs.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory = $true)][string]$Path)

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $encoding = [System.Text.UTF8Encoding]::new($false)
    $offset = 0
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $offset = 3 }
    elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) { $encoding = [System.Text.Encoding]::Unicode; $offset = 2 }
    elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) { $encoding = [System.Text.Encoding]::BigEndianUnicode; $offset = 2 }

    return @{ Bytes = $bytes; Text = $encoding.GetString($bytes, $offset, $bytes.Length - $offset) }
}

function Get-CCFSignatureStatus {
    <#
    .SYNOPSIS
        Checks the Authenticode signature of a plugin's bytes (or of the file when no bytes are given).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCompatibleCommands', '', Justification = 'Get-AuthenticodeSignature is only called after checking that it exists; elsewhere the plugin counts as unsigned.')]
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [byte[]]$Content
    )

    # Authenticode only exists on Windows. Elsewhere the signature cannot be verified, so the
    # plugin counts as unsigned (fail closed).
    $command = Get-Command -Name 'Get-AuthenticodeSignature' -ErrorAction SilentlyContinue
    if (-not $command) { return @{ Valid = $false; Status = 'NotSupportedOnPlatform' } }

    $sig = if ($Content) {
        Get-AuthenticodeSignature -SourcePathOrExtension $Path -Content $Content
    }
    else {
        Get-AuthenticodeSignature -LiteralPath $Path
    }

    if ($sig.Status -eq 'Valid') { return @{ Valid = $true; Status = 'Valid'; Signer = $sig.SignerCertificate.Subject } }
    return @{ Valid = $false; Status = $sig.Status.ToString() }
}

function Test-CCFPluginLocation {
    <#
    .SYNOPSIS
        True only when Path resolves to an existing .ps1 file inside the Plugins folder.
    .DESCRIPTION
        Paths are normalized first, so "Plugins\..\x.ps1" and sibling folders such as
        "PluginsX" are rejected.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try {
        $root = [System.IO.Path]::GetFullPath((Get-CCFPath -Target 'Plugins')).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
        $full = [System.IO.Path]::GetFullPath($Path)
    }
    catch { return $false }

    $comparison = if ($IsLinux -or $IsMacOS) { [StringComparison]::Ordinal } else { [StringComparison]::OrdinalIgnoreCase }
    if (-not $full.StartsWith($root, $comparison)) { return $false }
    if ([System.IO.Path]::GetExtension($full) -ne '.ps1') { return $false }
    return (Test-Path -LiteralPath $full -PathType Leaf)
}

function Invoke-CCFPluginCode {
    <#
    .SYNOPSIS
        Runs plugin code, in a new restricted runspace in ConstrainedLanguage mode with -Hardened.
    #>
    [CmdletBinding()]
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

# --- Public commands ---

function Confirm-CCFPluginSignature {
    <#
    .SYNOPSIS
        Checks whether a plugin file has a valid Authenticode signature.

    .DESCRIPTION
        Returns a hashtable with Valid ($true only for a valid, trusted signature), Status and,
        when valid, Signer. Self-signed certificates that are not trusted on the machine, and
        any platform without Authenticode (Linux, macOS), return Valid = $false: the check
        fails closed. Invoke-CCFPlugin runs this check on the exact bytes it is about to run
        when RequireSignedPlugins is enabled. The alias Test-CCFPluginSignature is kept for
        older scripts.

    .PARAMETER Path
        Path to the plugin file.

    .EXAMPLE
        (Confirm-CCFPluginSignature -Path .\Plugins\Backup\Backup.ps1).Valid

        Returns $true when the plugin is signed with a trusted certificate.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @{ Valid = $false; Status = 'FileNotFound' } }
    return (Get-CCFSignatureStatus -Path $Path)
}

function Get-CCFPlugin {
    <#
    .SYNOPSIS
        Lists the plugins in the Plugins folder (or another folder) with their metadata.

    .DESCRIPTION
        Finds every .ps1 file in the folder and its subfolders and returns one object per
        plugin with Name, Description, Version, Author, Path, Signed and Manifest.
        Metadata comes from a ccf_plugin.json file in the plugin's folder (Name, Version,
        Author, Description) or, failing that, from comment keywords in the script
        (.NAME, .DESCRIPTION, .VERSION, .AUTHOR, or CCF_PLUGIN_NAME: and similar).
        Listing a plugin does not run it. The alias Get-CCFPlugins is kept for older scripts.

    .PARAMETER Path
        Folder to search. Defaults to the module's Plugins folder.

    .EXAMPLE
        Get-CCFPlugin | Format-Table Name, Version, Signed

        Lists the installed plugins and whether they are signed.

    .EXAMPLE
        Get-CCFPlugin | Where-Object Name -EQ 'HelloWorld' | ForEach-Object { Invoke-CCFPlugin -Plugin $_ }

        Finds a plugin by name and runs it.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string]$Path = (Get-CCFPath -Target 'Plugins')
    )

    if (-not (Test-Path -LiteralPath $Path)) { return }

    foreach ($file in Get-ChildItem -LiteralPath $Path -Filter '*.ps1' -File -Recurse) {
        $plugin = [PSCustomObject]@{
            Name        = $null
            Description = 'No description'
            Version     = '1.0.0'
            Author      = 'Unknown'
            Path        = $file.FullName
            Signed      = (Confirm-CCFPluginSignature -Path $file.FullName).Valid
            Manifest    = $null
        }

        $manifestPath = Join-Path $file.DirectoryName 'ccf_plugin.json'
        if (Test-Path -LiteralPath $manifestPath) {
            try {
                $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
                if ($manifest) {
                    $plugin.Name = $manifest.Name
                    if ($manifest.Version) { $plugin.Version = $manifest.Version }
                    if ($manifest.Author) { $plugin.Author = $manifest.Author }
                    if ($manifest.Description) { $plugin.Description = $manifest.Description }
                    $plugin.Manifest = $manifest
                }
            }
            catch {
                Write-CCFLogWarn "Error al cargar manifiesto en $($file.Name): $($_.Exception.Message)"
            }
        }

        # Comment keywords, for plugins without a manifest.
        $content = (Read-CCFPluginFile -Path $file.FullName).Text
        if (-not $plugin.Name) {
            if ($content -match '\.NAME\s+(.+)') { $plugin.Name = $matches[1].Trim() }
            elseif ($content -match 'CCF_PLUGIN_NAME:\s*(.+)') { $plugin.Name = $matches[1].Trim() }
            else { $plugin.Name = $file.BaseName }
        }
        if ($plugin.Description -eq 'No description') {
            if ($content -match '\.DESCRIPTION\s+(.+)') { $plugin.Description = $matches[1].Trim() }
            elseif ($content -match 'CCF_PLUGIN_DESC:\s*(.+)') { $plugin.Description = $matches[1].Trim() }
        }
        if (-not $plugin.Manifest) {
            if ($content -match '\.VERSION\s+(.+)') { $plugin.Version = $matches[1].Trim() }
            elseif ($content -match 'CCF_PLUGIN_VERSION:\s*(.+)') { $plugin.Version = $matches[1].Trim() }
            if ($content -match '\.AUTHOR\s+(.+)') { $plugin.Author = $matches[1].Trim() }
            elseif ($content -match 'CCF_PLUGIN_AUTHOR:\s*(.+)') { $plugin.Author = $matches[1].Trim() }
        }

        $plugin
    }
}

function Invoke-CCFPlugin {
    <#
    .SYNOPSIS
        Runs a plugin from the Plugins folder, with its lifecycle hooks and optional sandboxing.

    .DESCRIPTION
        Checks, in order:
        1. The plugin must be a .ps1 file inside the module's Plugins folder (after resolving
           "..", so paths cannot escape it). Anything else is refused and logged as CRITICAL.
        2. When RequireSignedPlugins is enabled in the ccf_core configuration, the plugin must
           have a valid Authenticode signature. The signature is checked on the same bytes
           that are then run, so the file cannot be swapped between check and execution.
        Then it runs the plugin's Before-Execute function (if defined), the plugin script with
        -Arguments, and its After-Execute function with the result, and returns the result.
        With -HardenedMode the plugin and its hooks run in a new restricted runspace in
        ConstrainedLanguage mode: no cmdlets, no providers, and no calls to non-core .NET
        methods. This reduces what a plugin can do but is not a security boundary without
        WDAC or AppLocker; combine it with RequireSignedPlugins for code you did not write.
        Errors are logged with Write-CCFErrorRecord and the function returns $null.

    .PARAMETER Plugin
        Plugin object from Get-CCFPlugin, or any object with Name and Path.

    .PARAMETER Arguments
        Hashtable passed to the plugin (and to Before-Execute) as -Arguments.

    .PARAMETER SkipHooks
        Do not run Before-Execute and After-Execute.

    .PARAMETER HardenedMode
        Run the plugin and its hooks in a restricted ConstrainedLanguage runspace.

    .EXAMPLE
        $plugin = Get-CCFPlugin | Where-Object Name -EQ 'SystemInfo'
        Invoke-CCFPlugin -Plugin $plugin -Arguments @{ Detail = 'Full' }

        Runs the SystemInfo plugin with an argument.

    .EXAMPLE
        Invoke-CCFPlugin -Plugin $plugin -HardenedMode

        Runs the plugin in the restricted runspace.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Plugin,

        [hashtable]$Arguments = @{},

        [switch]$SkipHooks,

        [switch]$HardenedMode
    )

    # 1. Location
    if (-not (Test-CCFPluginLocation -Path $Plugin.Path)) {
        Write-CCFLogCritical "SECURITY BLOCK: plugin outside the Plugins folder was not run: $($Plugin.Path)"
        return $null
    }

    # Read once: the bytes that are checked are the bytes that run.
    $pluginFile = Read-CCFPluginFile -Path ([System.IO.Path]::GetFullPath($Plugin.Path))

    # 2. Signature
    $requireSigned = $false
    $coreConfig = Get-CCFConfig -ConfigName 'ccf_core'
    if ($coreConfig) { $requireSigned = $coreConfig.Security.RequireSignedPlugins -eq $true }

    if ($requireSigned) {
        $sigResult = Get-CCFSignatureStatus -Path $Plugin.Path -Content $pluginFile.Bytes
        if (-not $sigResult.Valid) {
            Write-CCFLogCritical "SECURITY BLOCK: plugin $($Plugin.Name) has no valid signature and RequireSignedPlugins is enabled."
            return $null
        }
        Write-CCFLogInfo "Valid signature: $($sigResult.Signer)"
    }

    if ($HardenedMode) {
        Write-CCFLogWarn "Running $($Plugin.Name) in hardened mode (ConstrainedLanguage)"
    }
    Write-CCFLogInfo "Running plugin: $($Plugin.Name)"

    $scriptText = $pluginFile.Text

    # Hooks are read from the plugin's AST instead of dot-sourcing the file, so defining
    # them does not run the plugin's main code a second time. Only the hook body's text is
    # kept: in HardenedMode it runs in the same restricted runspace as the plugin.
    $hooks = @{}
    if (-not $SkipHooks) {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($scriptText, [ref]$null, [ref]$null)
        foreach ($name in 'Before-Execute', 'After-Execute') {
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
        if ($hooks['Before-Execute']) {
            Write-CCFLogDebug 'Running the Before-Execute hook'
            $null = Invoke-CCFPluginCode -ScriptText $hooks['Before-Execute'] -Parameters @{ Arguments = $Arguments } -Hardened:$HardenedMode
        }

        $result = Invoke-CCFPluginCode -ScriptText $scriptText -Parameters @{ Arguments = $Arguments } -Hardened:$HardenedMode

        if ($hooks['After-Execute']) {
            Write-CCFLogDebug 'Running the After-Execute hook'
            $null = Invoke-CCFPluginCode -ScriptText $hooks['After-Execute'] -Parameters @{ Result = $result } -Hardened:$HardenedMode
        }

        Write-CCFLogSuccess "Plugin $($Plugin.Name) finished."
        return $result
    }
    catch {
        Write-CCFErrorRecord -ErrorRecord $_ -Context "PluginExecution:$($Plugin.Name)"
        return $null
    }
}

# Names from earlier versions, kept so existing scripts keep working.
New-Alias -Name Test-CCFPluginSignature -Value Confirm-CCFPluginSignature
New-Alias -Name Get-CCFPlugins -Value Get-CCFPlugin
