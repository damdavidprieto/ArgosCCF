# Plugin Creation Example

<#
.SYNOPSIS
Demonstrates how to create a plugin for ArgosCCF

.DESCRIPTION
Shows the complete process of creating, installing, and executing a plugin.
#>

# Import ArgosCCF
Import-Module "$PSScriptRoot\..\ArgosCCF.psd1" -Force

Init-CCFLogger -FileName "PluginCreation_Example.log"

Log-Header "=== Plugin Creation Demo ==="

# Step 1: Create plugin directory
$pluginDir = Join-Path (Get-CCFPath -Target "Plugins") "DemoPlugin"
if (-not (Test-Path $pluginDir)) {
    New-Item -ItemType Directory -Path $pluginDir -Force | Out-Null
}
Log-Success "Created plugin directory: $pluginDir"

# Step 2: Create plugin manifest
$manifest = @{
    Name        = "DemoPlugin"
    Version     = "1.0.0"
    Author      = "ArgosCCF Demo"
    Description = "A demonstration plugin showing lifecycle hooks"
}

$manifestPath = Join-Path $pluginDir "ccf_plugin.json"
$manifest | ConvertTo-Json | Set-Content $manifestPath -Force
Log-Success "Created plugin manifest"

# Step 3: Create plugin script with lifecycle hooks
$pluginScript = @'
<#
.NAME
DemoPlugin

.DESCRIPTION
Demonstration plugin with lifecycle hooks

.VERSION
1.0.0

.AUTHOR
ArgosCCF Demo
#>

param($Arguments)

function Before-Execute {
    param($Arguments)
    Log-Info "[DemoPlugin] Before-Execute hook called"
    Log-Info "[DemoPlugin] Initializing resources..."
}

function After-Execute {
    param($Result)
    Log-Info "[DemoPlugin] After-Execute hook called"
    Log-Info "[DemoPlugin] Cleaning up resources..."
    Log-Info "[DemoPlugin] Result was: $Result"
}

# Main plugin logic
Log-Info "[DemoPlugin] Main execution starting"

$taskName = if ($Arguments.TaskName) { $Arguments.TaskName } else { "DefaultTask" }
Log-Info "[DemoPlugin] Executing task: $taskName"

# Simulate some work
Start-Sleep -Milliseconds 500

$result = @{
    Status = "Success"
    Task = $taskName
    Timestamp = Get-Date
    Message = "Plugin executed successfully"
}

Log-Success "[DemoPlugin] Task completed"

return $result
'@

$pluginPath = Join-Path $pluginDir "DemoPlugin.ps1"
$pluginScript | Set-Content $pluginPath -Force
Log-Success "Created plugin script"

# Step 4: Discover the plugin
Log-Header "--- Discovering Plugins ---"
$plugins = Get-CCFPlugins
$demoPlugin = $plugins | Where-Object { $_.Name -eq "DemoPlugin" }

if ($demoPlugin) {
    Log-Success "Plugin discovered successfully"
    Write-Host "  Name: $($demoPlugin.Name)" -ForegroundColor Cyan
    Write-Host "  Version: $($demoPlugin.Version)" -ForegroundColor Cyan
    Write-Host "  Author: $($demoPlugin.Author)" -ForegroundColor Cyan
    Write-Host "  Description: $($demoPlugin.Description)" -ForegroundColor Cyan
}

# Step 5: Execute the plugin
Log-Header "--- Executing Plugin ---"

$result = Invoke-CCFPlugin -Plugin $demoPlugin -Arguments @{ TaskName = "BackupDatabase" }

Write-Host "`nPlugin Result:" -ForegroundColor Green
$result | Format-List

# Step 6: Execute in hardened mode (sandboxed)
Log-Header "--- Executing in Hardened Mode ---"

$hardenedResult = Invoke-CCFPlugin -Plugin $demoPlugin -Arguments @{ TaskName = "SecureOperation" } -HardenedMode

Write-Host "`nHardened Mode Result:" -ForegroundColor Green
$hardenedResult | Format-List

Log-Header "=== Plugin Creation Demo Complete ==="

Write-Host "`nYour plugin is located at: $pluginDir" -ForegroundColor Cyan
Write-Host "You can modify it and reload by running Get-CCFPlugins again" -ForegroundColor Yellow
