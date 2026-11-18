<#
.SYNOPSIS
    Builds ArgosCCF into output/ArgosCCF, ready to install or publish.

.DESCRIPTION
    Runs PSScriptAnalyzer with PSScriptAnalyzerSettings.psd1 and the Pester tests, then copies
    only the files the module needs at runtime into output/ArgosCCF and validates the
    result. Publish that folder, never the repository root, so tests, docs and .git never reach
    the PowerShell Gallery.

.PARAMETER InstallDependencies
    Install Pester 5 and PSScriptAnalyzer for the current user first.

.PARAMETER SkipAnalysis
    Do not run PSScriptAnalyzer.

.PARAMETER SkipTests
    Do not run the Pester tests.

.PARAMETER CodeCoverage
    Measure which lines of the runtime files the tests run, print the percentage and write
    output/coverage.xml (JaCoCo format). On GitHub Actions the result is also added to the run
    summary. It is reported, not enforced.

.EXAMPLE
    ./build.ps1 -InstallDependencies

.EXAMPLE
    ./build.ps1 -SkipTests
#>
[CmdletBinding()]
param(
    [switch]$InstallDependencies,
    [switch]$SkipAnalysis,
    [switch]$SkipTests,
    [switch]$CodeCoverage
)

$ErrorActionPreference = 'Stop'
$moduleName = 'ArgosCCF'
$testsPath = Join-Path $PSScriptRoot 'Tests'
$outputDir = Join-Path $PSScriptRoot "output/$moduleName"

# Files and folders the module needs at runtime.
$runtimeItems = @(
    "$moduleName.psd1"
    "$moduleName.psm1"
    'LICENSE'
    'README.md'
    'Core'
    'Configs/Factory'
    'Plugins/Examples'
)

if ($InstallDependencies) {
    Install-Module Pester -MinimumVersion 5.0.0 -MaximumVersion 5.99.99 -Force -SkipPublisherCheck -Scope CurrentUser
    Install-Module PSScriptAnalyzer -Force -SkipPublisherCheck -Scope CurrentUser
}

if (-not $SkipAnalysis) {
    Write-Host 'Running PSScriptAnalyzer...' -ForegroundColor Cyan
    $settings = Join-Path $PSScriptRoot 'PSScriptAnalyzerSettings.psd1'
    $sources = $runtimeItems | ForEach-Object { Join-Path $PSScriptRoot $_ } |
        Get-ChildItem -Recurse -Include '*.ps1', '*.psm1', '*.psd1' -File
    # PSScriptAnalyzer 1.2x sometimes throws a NullReferenceException while it loads its rules
    # (the message depends on the Windows language). The same call succeeds when repeated, so
    # each file gets up to three attempts; a third failure is reported.
    $issues = foreach ($source in $sources) {
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            try { Invoke-ScriptAnalyzer -Path $source.FullName -Settings $settings -ErrorAction Stop; break }
            catch { if ($attempt -eq 3) { throw }; Write-Verbose "Retrying $($source.Name): $($_.Exception.Message)"; Start-Sleep -Seconds 1 }
        }
    }
    if ($issues) {
        $issues | Format-Table RuleName, Severity, ScriptName, Line, Message -AutoSize -Wrap | Out-Host
        throw "PSScriptAnalyzer found $(@($issues).Count) issue(s)."
    }
}

if (-not $SkipTests) {
    Write-Host 'Running Pester tests...' -ForegroundColor Cyan
    $config = New-PesterConfiguration
    $config.Run.Path = $testsPath
    $config.Run.PassThru = $true
    $config.Output.Verbosity = 'Normal'
    if ($CodeCoverage) {
        $config.CodeCoverage.Enabled = $true
        $config.CodeCoverage.Path = @(
            Join-Path $PSScriptRoot "$moduleName.psm1"
            Get-ChildItem -Path (Join-Path $PSScriptRoot 'Core') -Filter '*.ps1' | ForEach-Object FullName
        )
        $config.CodeCoverage.OutputFormat = 'JaCoCo'
        $null = New-Item -ItemType Directory -Path (Join-Path $PSScriptRoot 'output') -Force
        $config.CodeCoverage.OutputPath = Join-Path $PSScriptRoot 'output/coverage.xml'
    }
    # The tests write logs and user settings to a temporary data folder, never to your own.
    $previousDataPath = $env:CCF_DATA_PATH
    $env:CCF_DATA_PATH = Join-Path ([System.IO.Path]::GetTempPath()) ('ArgosCCF-tests-' + [guid]::NewGuid().ToString('N'))
    try { $result = Invoke-Pester -Configuration $config }
    finally {
        Remove-Item -LiteralPath $env:CCF_DATA_PATH -Recurse -Force -ErrorAction SilentlyContinue
        $env:CCF_DATA_PATH = $previousDataPath
    }
    if ($result.FailedCount -gt 0) {
        throw "$($result.FailedCount) test(s) failed."
    }
    if ($CodeCoverage -and $result.CodeCoverage) {
        $coverage = $result.CodeCoverage
        $percent = [math]::Round($coverage.CoveragePercent, 1)
        Write-Host "Code coverage: $percent% ($($coverage.CommandsExecutedCount) of $($coverage.CommandsAnalyzedCount) commands)" -ForegroundColor Cyan
        if ($env:GITHUB_STEP_SUMMARY) {
            $byFile = $coverage.CommandsMissed | Group-Object { Split-Path $_.File -Leaf } | Sort-Object Count -Descending |
                ForEach-Object { "| $($_.Name) | $($_.Count) |" }
            $summary = @("### Code coverage: $percent%", '', "$($coverage.CommandsExecutedCount) of $($coverage.CommandsAnalyzedCount) commands run by the tests.", '', '| File | Commands not run |', '|---|---|') + $byFile
            Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value $summary -Encoding utf8
        }
    }
}

Write-Host "Building $outputDir..." -ForegroundColor Cyan
if (Test-Path $outputDir) { Remove-Item $outputDir -Recurse -Force }
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

foreach ($item in $runtimeItems) {
    $source = Join-Path $PSScriptRoot $item
    $destination = Join-Path $outputDir $item
    New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
    Copy-Item -Path $source -Destination $destination -Recurse -Force
}

$manifest = Test-ModuleManifest -Path (Join-Path $outputDir "$moduleName.psd1")
$forbidden = '.git', '.github', 'tests', 'docs', 'examples', 'logs', 'output', 'user'
$unexpected = @(Get-ChildItem $outputDir -Force | Where-Object { $_.Name -in $forbidden }) +
    @(Get-ChildItem $outputDir -Recurse -Force -File | Where-Object { $_.Extension -in '.log', '.nupkg' })
if ($unexpected) {
    throw "Build output contains files that must not be published: $($unexpected.FullName -join ', ')"
}

Write-Host "Built $moduleName $($manifest.Version) in $outputDir" -ForegroundColor Green
