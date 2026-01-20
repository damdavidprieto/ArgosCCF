# build.ps1 - ArgosCCF Build & Test Automation

param(
    [switch]$InstallDependencies,
    [switch]$SkipTests,
    [switch]$Publish
)

$ErrorActionPreference = "Stop"

Write-Host "🚀 Starting ArgosCCF Build..." -ForegroundColor Cyan

if ($InstallDependencies) {
    Write-Host "📦 Installing dependencies (Pester, PSScriptAnalyzer)..." -ForegroundColor Yellow
    Install-Module Pester -Force -SkipPublisherCheck -ErrorAction SilentlyContinue
    Install-Module PSScriptAnalyzer -Force -SkipPublisherCheck -ErrorAction SilentlyContinue
}

# 1. Static Code Analysis
Write-Host "🔍 Running PSScriptAnalyzer..." -ForegroundColor Cyan
$saResults = Invoke-ScriptAnalyzer -Path "$PSScriptRoot" -Recurse -Severity Error, Warning
if ($saResults) {
    $saResults | Format-Table
    if ($saResults | Where-Object { $_.Severity -eq "Error" }) {
        Write-Error "Build Failed: PSScriptAnalyzer found errors."
    }
}
else {
    Write-Host "✅ Code Analysis Passed." -ForegroundColor Green
}

# 2. Testing
if (-not $SkipTests) {
    Write-Host "🧪 Running Pester Tests..." -ForegroundColor Cyan
    $pester = Invoke-Pester -Path "$PSScriptRoot\Tests" -PassThru -Output Detailed
    if ($pester.FailedCount -gt 0) {
        Write-Error "Build Failed: $($pester.FailedCount) tests failed."
    }
    Write-Host "✅ All Tests Passed." -ForegroundColor Green
}

# 3. Validation
Write-Host "📋 Validating Module Manifest..." -ForegroundColor Cyan
Test-ModuleManifest -Path "$PSScriptRoot\ArgosCCF.psd1" | Out-Null
Write-Host "✅ Manifest Valid." -ForegroundColor Green

Write-Host "🎉 Build Complete!" -ForegroundColor Green

if ($Publish) {
    Write-Host "🚀 Publishing to PowerShell Gallery (Simulation)..." -ForegroundColor Yellow
    # Publish-Module -Path "$PSScriptRoot" -NuGetApiKey $env:NuGetApiKey
    Write-Host "✅ Published (Simulated)." -ForegroundColor Green
}
