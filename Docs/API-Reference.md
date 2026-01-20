# ArgosCCF API Reference

## Core Functions

### Path Management

#### `Get-CCFPath`

Resolves paths to ArgosCCF directories with security validation.

**Syntax:**
```powershell
Get-CCFPath -Target <String>
```

**Parameters:**
- `-Target`: Directory target. Valid values: `Root`, `Core`, `Configs`, `Logs`, `Tests`, `Plugins`

**Returns:** `[string]` - Absolute path to the requested directory

**Example:**
```powershell
$logDir = Get-CCFPath -Target "Logs"
# Returns: C:\test\ArgosCCF\Logs
```

---

## Logging Functions

### `Init-CCFLogger`

Initializes the logging system with file rotation.

**Syntax:**
```powershell
Init-CCFLogger [-FileName <String>] [-MaxMB <Int>] [-MaxRolling <Int>]
```

**Parameters:**
- `-FileName`: Log file name (default: `CCF_Session.log`)
- `-MaxMB`: Maximum log file size in MB before rotation (default: `10`)
- `-MaxRolling`: Number of rotated log files to keep (default: `5`)

**Example:**
```powershell
Init-CCFLogger -FileName "MyApp.log" -MaxMB 50 -MaxRolling 10
```

---

### `Write-CCFLog`

Core logging function (typically called via helper functions).

**Syntax:**
```powershell
Write-CCFLog -Message <String> [-Level <String>] [-Category <String>] [-Data <Object>] [-Color <String>]
```

**Parameters:**
- `-Message`: Log message
- `-Level`: Log level (`INFO`, `WARN`, `ERROR`, `SUCCESS`, `CRITICAL`, `DEBUG`)
- `-Category`: Log category (default: `System`)
- `-Data`: Additional structured data
- `-Color`: Console color override

---

### `Log-Info`

Logs informational messages.

**Syntax:**
```powershell
Log-Info -Message <String>
```

**Example:**
```powershell
Log-Info "Application started successfully"
```

---

### `Log-Warn`

Logs warning messages.

**Syntax:**
```powershell
Log-Warn -Message <String>
```

**Example:**
```powershell
Log-Warn "Disk space running low"
```

---

### `Log-Error`

Logs error messages.

**Syntax:**
```powershell
Log-Error -Message <String>
```

**Example:**
```powershell
Log-Error "Failed to connect to database"
```

---

### `Log-Success`

Logs success messages.

**Syntax:**
```powershell
Log-Success -Message <String>
```

**Example:**
```powershell
Log-Success "Backup completed successfully"
```

---

### `Log-Critical`

Logs critical error messages.

**Syntax:**
```powershell
Log-Critical -Message <String>
```

**Example:**
```powershell
Log-Critical "System failure detected - shutting down"
```

---

### `Log-Debug`

Logs debug messages.

**Syntax:**
```powershell
Log-Debug -Message <String>
```

**Example:**
```powershell
Log-Debug "Variable value: $myVar"
```

---

### `Log-Header`

Logs formatted header messages.

**Syntax:**
```powershell
Log-Header -Message <String>
```

**Example:**
```powershell
Log-Header "=== Starting Backup Process ==="
```

---

### `Log-Attack`

Logs security attack attempts.

**Syntax:**
```powershell
Log-Attack -Type <String> -Source <String> -Payload <String>
```

**Parameters:**
- `-Type`: Attack type (e.g., `PathTraversal`, `Injection`)
- `-Source`: Attack source
- `-Payload`: Attack payload

**Example:**
```powershell
Log-Attack -Type "PathTraversal" -Source "UserInput" -Payload "../../../etc/passwd"
```

---

### `Catch-CCFError`

Logs exceptions with full context.

**Syntax:**
```powershell
Catch-CCFError -ErrorRecord <ErrorRecord> [-Context <String>]
```

**Example:**
```powershell
try {
    # Risky operation
}
catch {
    Catch-CCFError -ErrorRecord $_ -Context "DatabaseOperation"
}
```

---

## Configuration Functions

### `Get-CCFConfig`

Loads configuration with layered merging (Factory → Presets → User).

**Syntax:**
```powershell
Get-CCFConfig -ConfigName <String> [-ActivePresets <String[]>] [-ForceRefresh]
```

**Parameters:**
- `-ConfigName`: Configuration name (without `.json` extension)
- `-ActivePresets`: Array of preset names to apply
- `-ForceRefresh`: Bypass cache and reload from disk

**Returns:** `[PSCustomObject]` - Merged configuration object

**Example:**
```powershell
$config = Get-CCFConfig -ConfigName "app_settings" -ActivePresets @("production")
```

---

### `Set-CCFUserConfig`

Saves user-specific configuration overrides.

**Syntax:**
```powershell
Set-CCFUserConfig -ConfigName <String> -ConfigObject <PSCustomObject>
```

**Parameters:**
- `-ConfigName`: Configuration name
- `-ConfigObject`: Configuration object to save

**Example:**
```powershell
$userConfig = @{ Database = @{ Host = "localhost" } }
Set-CCFUserConfig -ConfigName "app_settings" -ConfigObject $userConfig
```

---

### `Clear-CCFConfigCache`

Clears the in-memory configuration cache.

**Syntax:**
```powershell
Clear-CCFConfigCache
```

**Example:**
```powershell
Clear-CCFConfigCache
```

---

### `Test-CCFConfigSchema`

Validates configuration against a schema.

**Syntax:**
```powershell
Test-CCFConfigSchema -Config <PSCustomObject> -Schema <Hashtable>
```

**Parameters:**
- `-Config`: Configuration object to validate
- `-Schema`: Schema definition (hashtable with expected types)

**Returns:** `[bool]` - `$true` if valid, `$false` otherwise

**Example:**
```powershell
$schema = @{
    Database = @{
        Host = [string]
        Port = [int]
    }
}
$isValid = Test-CCFConfigSchema -Config $config -Schema $schema
```

---

## Plugin Functions

### `Get-CCFPlugins`

Discovers available plugins.

**Syntax:**
```powershell
Get-CCFPlugins [-Path <String>]
```

**Parameters:**
- `-Path`: Custom plugin directory (default: `Plugins/`)

**Returns:** `[PSCustomObject[]]` - Array of plugin objects

**Example:**
```powershell
$plugins = Get-CCFPlugins
foreach ($plugin in $plugins) {
    Write-Host "$($plugin.Name) v$($plugin.Version)"
}
```

---

### `Invoke-CCFPlugin`

Executes a plugin with optional sandboxing.

**Syntax:**
```powershell
Invoke-CCFPlugin -Plugin <PSCustomObject> [-Arguments <Hashtable>] [-SkipHooks] [-HardenedMode]
```

**Parameters:**
- `-Plugin`: Plugin object from `Get-CCFPlugins`
- `-Arguments`: Arguments to pass to the plugin
- `-SkipHooks`: Skip lifecycle hooks (Before-Execute, After-Execute)
- `-HardenedMode`: Execute in Constrained Language Mode

**Returns:** `[Object]` - Plugin return value

**Example:**
```powershell
$plugin = Get-CCFPlugins | Where-Object { $_.Name -eq "MyPlugin" }
$result = Invoke-CCFPlugin -Plugin $plugin -Arguments @{ Task = "Backup" } -HardenedMode
```

---

### `Test-CCFPluginSignature`

Verifies plugin authenticode signature.

**Syntax:**
```powershell
Test-CCFPluginSignature -Path <String>
```

**Parameters:**
- `-Path`: Path to plugin file

**Returns:** `[Hashtable]` - Signature validation result

**Example:**
```powershell
$sigResult = Test-CCFPluginSignature -Path "C:\Plugins\MyPlugin.ps1"
if ($sigResult.Valid) {
    Write-Host "Plugin is signed by: $($sigResult.Signer)"
}
```

---

## Execution Functions

### `Invoke-CCFParallel`

Executes a script block in parallel across multiple inputs.

**Syntax:**
```powershell
Invoke-CCFParallel -ScriptBlock <ScriptBlock> -InputObjects <Array> [-MaxThreads <Int>] [-Arguments <Hashtable>] [-RetryCount <Int>] [-RetryDelayMs <Int>]
```

**Parameters:**
- `-ScriptBlock`: Script block to execute
- `-InputObjects`: Array of objects to process
- `-MaxThreads`: Maximum concurrent threads (default: CPU count)
- `-Arguments`: Additional arguments to pass
- `-RetryCount`: Number of retries on failure (default: `0`)
- `-RetryDelayMs`: Delay between retries in milliseconds (default: `500`)

**Returns:** `[PSCustomObject[]]` - Array of results with status

**Example:**
```powershell
$servers = @('Server01', 'Server02', 'Server03')
$scriptBlock = {
    param($server)
    Test-Connection -ComputerName $server -Count 1 -Quiet
}
$results = Invoke-CCFParallel -ScriptBlock $scriptBlock -InputObjects $servers -MaxThreads 4
```

---

## Internal Functions

The following functions are exported but primarily for internal use:

- `Redact-CCFSensitiveData` - Secret sanitization
- `Test-CCFHighEntropy` - Entropy detection
- `Merge-CCFConfig` - Configuration merging
- `Register-CCFLogProvider` - Custom log provider registration
