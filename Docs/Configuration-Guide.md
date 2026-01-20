# Configuration Guide

## Overview

ArgosCCF uses a powerful layered configuration system that merges settings from three sources:
1. **Factory** - Default configurations (version controlled)
2. **Presets** - Environment-specific settings (dev, staging, prod)
3. **User** - Local overrides (not version controlled)

## Configuration Hierarchy

```
Factory (Base)
    ↓
Presets (Environment)
    ↓
User (Local Overrides)
    ↓
Final Configuration
```

## Directory Structure

```
Configs/
├── Factory/          # Default configurations (committed to git)
│   ├── app_settings.json
│   └── ccf_core.json
├── Presets/          # Environment presets (committed to git)
│   ├── development.json
│   └── production.json
└── User/             # Local overrides (gitignored)
    └── app_settings.json
```

## Creating a Configuration

### 1. Factory Configuration

Create `Configs/Factory/app_settings.json`:

```json
{
    "Database": {
        "Host": "localhost",
        "Port": 5432,
        "Name": "myapp",
        "Timeout": 30
    },
    "Logging": {
        "Level": "INFO",
        "MaxSizeMB": 100
    },
    "Features": {
        "EnableCache": true,
        "EnableMetrics": false
    }
}
```

### 2. Preset Configuration

Create `Configs/Presets/production.json`:

```json
{
    "app_settings": {
        "Database": {
            "Host": "prod-db.example.com",
            "Timeout": 60
        },
        "Logging": {
            "Level": "WARN"
        },
        "Features": {
            "EnableMetrics": true
        }
    }
}
```

### 3. User Configuration

Create `Configs/User/app_settings.json`:

```json
{
    "Database": {
        "Host": "127.0.0.1"
    }
}
```

## Loading Configurations

### Basic Load

```powershell
# Load with defaults only
$config = Get-CCFConfig -ConfigName "app_settings"
```

### With Presets

```powershell
# Load with production preset
$config = Get-CCFConfig -ConfigName "app_settings" -ActivePresets @("production")

# Load with multiple presets (applied in order)
$config = Get-CCFConfig -ConfigName "app_settings" -ActivePresets @("base", "production", "region-eu")
```

### Force Refresh

```powershell
# Bypass cache and reload from disk
$config = Get-CCFConfig -ConfigName "app_settings" -ForceRefresh
```

## Deep Merging

ArgosCCF performs deep merging of nested objects:

**Factory:**
```json
{
    "Database": {
        "Host": "localhost",
        "Port": 5432,
        "Options": {
            "SSL": false,
            "Pooling": true
        }
    }
}
```

**User:**
```json
{
    "Database": {
        "Host": "prod-server",
        "Options": {
            "SSL": true
        }
    }
}
```

**Result:**
```json
{
    "Database": {
        "Host": "prod-server",      // Overridden
        "Port": 5432,                // From factory
        "Options": {
            "SSL": true,             // Overridden
            "Pooling": true          // From factory
        }
    }
}
```

## Saving User Configurations

```powershell
# Create user override
$userConfig = [PSCustomObject]@{
    Database = @{
        Host = "localhost"
        Port = 5433
    }
}

# Save (automatically invalidates cache)
Set-CCFUserConfig -ConfigName "app_settings" -ConfigObject $userConfig
```

## Schema Validation

Validate configuration structure:

```powershell
$config = Get-CCFConfig -ConfigName "app_settings"

$schema = @{
    Database = @{
        Host = [string]
        Port = [int]
    }
    Logging = @{
        Level = [string]
    }
}

$isValid = Test-CCFConfigSchema -Config $config -Schema $schema
```

## Performance: Caching

ArgosCCF caches loaded configurations in memory:

```powershell
# First call: reads from disk
$config1 = Get-CCFConfig -ConfigName "app_settings"

# Second call: returns from cache (fast)
$config2 = Get-CCFConfig -ConfigName "app_settings"

# Clear cache manually if needed
Clear-CCFConfigCache
```

## Best Practices

1. **Version Control**: Commit Factory and Presets, gitignore User configs
2. **Sensitive Data**: Never store secrets in configs; use environment variables or secret managers
3. **Naming**: Use descriptive config names (e.g., `database_settings`, not `config1`)
4. **Presets**: Create presets for each environment (dev, staging, prod)
5. **Validation**: Always validate critical configurations with schemas
6. **Documentation**: Document expected configuration structure in README

## Example: Multi-Environment Setup

```powershell
# Development
$config = Get-CCFConfig -ConfigName "app_settings" -ActivePresets @("development")

# Staging
$config = Get-CCFConfig -ConfigName "app_settings" -ActivePresets @("staging")

# Production
$config = Get-CCFConfig -ConfigName "app_settings" -ActivePresets @("production")
```
