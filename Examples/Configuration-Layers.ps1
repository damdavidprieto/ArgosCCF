# Configuration Layers Example

<#
.SYNOPSIS
Demonstrates ArgosCCF's layered configuration system

.DESCRIPTION
Shows how Factory, Preset, and User configurations merge together.
#>

# Import ArgosCCF
Import-Module "$PSScriptRoot\..\ArgosCCF.psd1" -Force

Init-CCFLogger -FileName "ConfigLayers_Example.log"

Log-Header "=== Configuration Layers Demo ==="

# Setup: Create example configurations
$configsPath = Get-CCFPath -Target "Configs"

# 1. Create Factory configuration (base defaults)
$factoryPath = Join-Path $configsPath "Factory"
if (-not (Test-Path $factoryPath)) { New-Item -ItemType Directory -Path $factoryPath -Force | Out-Null }

$factoryConfig = @{
    Database = @{
        Host    = "localhost"
        Port    = 5432
        Timeout = 30
        SSL     = $false
    }
    Logging  = @{
        Level     = "INFO"
        MaxSizeMB = 100
    }
    Features = @{
        EnableCache   = $true
        EnableMetrics = $false
    }
}

$factoryConfig | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $factoryPath "demo_app.json")
Log-Success "Created Factory configuration"

# 2. Create Production preset
$presetsPath = Join-Path $configsPath "Presets"
if (-not (Test-Path $presetsPath)) { New-Item -ItemType Directory -Path $presetsPath -Force | Out-Null }

$productionPreset = @{
    demo_app = @{
        Database = @{
            Host    = "prod-db.example.com"
            Timeout = 60
            SSL     = $true
        }
        Logging  = @{
            Level = "WARN"
        }
        Features = @{
            EnableMetrics = $true
        }
    }
}

$productionPreset | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $presetsPath "production.json")
Log-Success "Created Production preset"

# 3. Create User override
$userPath = Join-Path $configsPath "User"
if (-not (Test-Path $userPath)) { New-Item -ItemType Directory -Path $userPath -Force | Out-Null }

$userConfig = @{
    Database = @{
        Host = "127.0.0.1"
        Port = 5433
    }
}

$userConfig | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $userPath "demo_app.json")
Log-Success "Created User configuration"

# Load configurations with different layers
Log-Header "--- Loading Configurations ---"

# Load with Factory only
Log-Info "Loading with Factory defaults only..."
$config1 = Get-CCFConfig -ConfigName "demo_app" -ForceRefresh
Write-Host "Database Host: $($config1.Database.Host)" -ForegroundColor Yellow
Write-Host "Database SSL: $($config1.Database.SSL)" -ForegroundColor Yellow
Write-Host "Logging Level: $($config1.Logging.Level)" -ForegroundColor Yellow

# Load with Production preset
Log-Info "`nLoading with Production preset..."
$config2 = Get-CCFConfig -ConfigName "demo_app" -ActivePresets @("production") -ForceRefresh
Write-Host "Database Host: $($config2.Database.Host)" -ForegroundColor Cyan
Write-Host "Database SSL: $($config2.Database.SSL)" -ForegroundColor Cyan
Write-Host "Logging Level: $($config2.Logging.Level)" -ForegroundColor Cyan
Write-Host "Metrics Enabled: $($config2.Features.EnableMetrics)" -ForegroundColor Cyan

# Load with Production preset + User overrides
Log-Info "`nLoading with Production preset + User overrides..."
$config3 = Get-CCFConfig -ConfigName "demo_app" -ActivePresets @("production") -ForceRefresh
Write-Host "Database Host: $($config3.Database.Host) (User override)" -ForegroundColor Green
Write-Host "Database Port: $($config3.Database.Port) (User override)" -ForegroundColor Green
Write-Host "Database SSL: $($config3.Database.SSL) (From Production)" -ForegroundColor Green
Write-Host "Logging Level: $($config3.Logging.Level) (From Production)" -ForegroundColor Green

# Demonstrate caching
Log-Header "--- Caching Demo ---"
Log-Info "First load (from disk)..."
$start1 = Get-Date
$config4 = Get-CCFConfig -ConfigName "demo_app"
$time1 = (Get-Date) - $start1

Log-Info "Second load (from cache)..."
$start2 = Get-Date
$config5 = Get-CCFConfig -ConfigName "demo_app"
$time2 = (Get-Date) - $start2

Write-Host "First load: $($time1.TotalMilliseconds)ms" -ForegroundColor Yellow
Write-Host "Cached load: $($time2.TotalMilliseconds)ms (faster!)" -ForegroundColor Green

Log-Header "=== Configuration Demo Complete ==="
