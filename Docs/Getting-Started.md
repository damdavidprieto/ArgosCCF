# Getting Started with ArgosCCF

## Introduction

**ArgosCCF** is a professional PowerShell framework designed for secure automation, configuration management, and high-performance parallel execution. This guide will help you get started quickly.

## Installation

### From PowerShell Gallery (not yet published)

```powershell
Install-Module -Name ArgosCCF -Scope CurrentUser
Import-Module ArgosCCF
```

### From Source

1. Clone the repository:
```powershell
git clone https://github.com/damdavidprieto/ArgosCCF.git
cd ArgosCCF
```

2. Import the module:
```powershell
Import-Module .\ArgosCCF.psd1
```

## Quick Start

### 1. Initialize Logging

```powershell
# Initialize the logger with a custom filename
Init-CCFLogger -FileName "MyApp.log" -MaxMB 50 -MaxRolling 5

# Log messages at different levels
Log-Info "Application started"
Log-Warn "Low disk space detected"
Log-Error "Failed to connect to database"
Log-Success "Operation completed successfully"
Log-Critical "System failure detected"
```

### 2. Configuration Management

ArgosCCF uses a layered configuration system (Factory → Presets → User):

```powershell
# Load a configuration
$config = Get-CCFConfig -ConfigName "app_settings"

# Access configuration values
Write-Host "Database: $($config.Database.Host)"

# Save user-specific overrides
$userConfig = @{
    Database = @{
        Host = "localhost"
        Port = 5432
    }
}
Set-CCFUserConfig -ConfigName "app_settings" -ConfigObject $userConfig
```

### 3. Plugin System

```powershell
# Discover available plugins
$plugins = Get-CCFPlugins

# Execute a plugin
$result = Invoke-CCFPlugin -Plugin $plugins[0] -Arguments @{ TaskName = "Backup" }

# Execute with security hardening (Constrained Language Mode)
$result = Invoke-CCFPlugin -Plugin $plugins[0] -HardenedMode
```

### 4. Parallel Execution

```powershell
# Define a task
$scriptBlock = {
    param($server)
    Test-Connection -ComputerName $server -Count 1 -Quiet
}

# Execute in parallel across multiple servers
$servers = @('Server01', 'Server02', 'Server03')
$results = Invoke-CCFParallel -ScriptBlock $scriptBlock -InputObjects $servers -MaxThreads 4

# Process results
foreach ($result in $results) {
    Write-Host "$($result.Target): $($result.Status)"
}
```

## Next Steps

- Read the [Configuration Guide](Configuration-Guide.md) for advanced configuration scenarios
- Learn how to create plugins in the [Plugin Development Guide](Plugin-Development.md)
- Review [Security Best Practices](Security.md)
- Check the [API Reference](API-Reference.md) for complete function documentation

## Example Scripts

See the `Examples/` directory for complete working examples:
- `Demo.ps1` - Full integration demo
- `Basic-Logging.ps1` - Logging examples
- `Configuration-Layers.ps1` - Configuration merging
- `Parallel-Execution.ps1` - Multi-threaded tasks
