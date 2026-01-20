# Plugin Development Guide

## Overview

ArgosCCF's plugin system allows you to extend the framework with custom functionality while maintaining security and isolation.

## Plugin Structure

### Basic Plugin

A minimal plugin is a PowerShell script (`.ps1`) with metadata:

```powershell
<#
.NAME
MyPlugin

.DESCRIPTION
A simple example plugin

.VERSION
1.0.0

.AUTHOR
Your Name
#>

param($Arguments)

Write-Host "Hello from MyPlugin!"
return "Success"
```

### Plugin with Manifest (Recommended)

Create a `ccf_plugin.json` file alongside your plugin:

**ccf_plugin.json:**
```json
{
    "Name": "MyPlugin",
    "Version": "2.0.0",
    "Author": "Your Name",
    "Description": "Advanced plugin with manifest"
}
```

**MyPlugin.ps1:**
```powershell
param($Arguments)

Log-Info "Executing MyPlugin v2.0.0"
# Your plugin logic here
return @{ Status = "Success"; Data = $Arguments }
```

## Lifecycle Hooks

Plugins can implement lifecycle hooks for setup and teardown:

```powershell
function Before-Execute {
    param($Arguments)
    Log-Info "Initializing plugin resources..."
    # Setup code here
}

function After-Execute {
    param($Result)
    Log-Info "Cleaning up plugin resources..."
    # Cleanup code here
}

# Main execution
param($Arguments)
Log-Info "Main plugin logic executing"
return "Result"
```

## Security Features

### Signature Verification

For production environments, sign your plugins:

```powershell
# Get your code signing certificate
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert

# Sign the plugin
Set-AuthenticodeSignature -FilePath "MyPlugin.ps1" -Certificate $cert
```

Enable signature verification in `Configs/Factory/ccf_core.json`:

```json
{
    "Security": {
        "RequireSignedPlugins": true
    }
}
```

### Sandboxing

Execute plugins in Constrained Language Mode for maximum security:

```powershell
$result = Invoke-CCFPlugin -Plugin $myPlugin -HardenedMode
```

## Best Practices

1. **Use Manifests**: Always provide a `ccf_plugin.json` for metadata
2. **Parameter Validation**: Validate all input parameters
3. **Error Handling**: Use try/catch and log errors appropriately
4. **Return Values**: Return structured data (hashtables or PSCustomObjects)
5. **Logging**: Use ArgosCCF logging functions (Log-Info, Log-Error, etc.)
6. **Avoid Global State**: Keep plugins self-contained

## Example: System Info Plugin

**SystemInfo.ps1:**
```powershell
<#
.NAME
SystemInfo

.DESCRIPTION
Collects system information

.VERSION
1.0.0
#>

param($Arguments)

try {
    $info = @{
        Hostname = $env:COMPUTERNAME
        OS = (Get-CimInstance Win32_OperatingSystem).Caption
        Memory = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
        Uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    }
    
    Log-Success "System info collected successfully"
    return $info
}
catch {
    Log-Error "Failed to collect system info: $($_.Exception.Message)"
    return $null
}
```

## Testing Your Plugin

```powershell
# Load ArgosCCF
Import-Module ArgosCCF

# Place your plugin in the Plugins directory
Copy-Item "MyPlugin.ps1" -Destination (Get-CCFPath -Target "Plugins")

# Discover and execute
$plugins = Get-CCFPlugins
$myPlugin = $plugins | Where-Object { $_.Name -eq "MyPlugin" }
$result = Invoke-CCFPlugin -Plugin $myPlugin
```
