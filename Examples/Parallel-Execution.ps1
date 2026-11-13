# Parallel Execution Example

<#
.SYNOPSIS
Demonstrates ArgosCCF's parallel execution capabilities

.DESCRIPTION
Shows how to use Invoke-CCFParallel for high-performance multi-threaded operations.
#>

# Import ArgosCCF
Import-Module "$PSScriptRoot\..\ArgosCCF.psd1" -Force

Init-CCFLogger -FileName "ParallelExecution_Example.log"

Log-Header "=== Parallel Execution Demo ==="

# Example 1: Ping multiple servers in parallel
Log-Info "Example 1: Parallel Server Ping"

$servers = @('google.com', 'microsoft.com', 'github.com', 'stackoverflow.com')

$pingScript = {
    param($server)
    $result = Test-Connection -ComputerName $server -Count 1 -Quiet
    return @{
        Server    = $server
        Online    = $result
        Timestamp = Get-Date
    }
}

$pingResults = Invoke-CCFParallel -ScriptBlock $pingScript -InputObjects $servers -MaxThreads 4

foreach ($result in $pingResults) {
    $status = if ($result.Output.Online) { "✓ ONLINE" } else { "✗ OFFLINE" }
    $color = if ($result.Output.Online) { "Green" } else { "Red" }
    Write-Host "$($result.Target): $status" -ForegroundColor $color
}

# Example 2: Process files in parallel
Log-Info "`nExample 2: Parallel File Processing"

$numbers = 1..10

$processScript = {
    param($number)
    Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum 500)
    return $number * $number
}

$start = Get-Date
$results = Invoke-CCFParallel -ScriptBlock $processScript -InputObjects $numbers -MaxThreads 4
$duration = (Get-Date) - $start

Write-Host "`nProcessed $($numbers.Count) items in $($duration.TotalSeconds) seconds" -ForegroundColor Cyan
foreach ($result in $results) {
    Write-Host "$($result.Target)² = $($result.Output)" -ForegroundColor Yellow
}

# Example 3: Parallel with retry logic
Log-Info "`nExample 3: Parallel with Automatic Retries"

$unreliableScript = {
    param($item)
    # Simulate 50% failure rate
    if ((Get-Random -Minimum 0 -Maximum 2) -eq 0) {
        throw "Simulated failure"
    }
    return "Success: $item"
}

$items = 1..5
$retryResults = Invoke-CCFParallel -ScriptBlock $unreliableScript -InputObjects $items -MaxThreads 2 -RetryCount 3

foreach ($result in $retryResults) {
    $statusColor = if ($result.Status -eq "Success") { "Green" } else { "Red" }
    Write-Host "Item $($result.Target): $($result.Status) (Retries: $($result.Retries))" -ForegroundColor $statusColor
}

# Example 4: Performance comparison
Log-Header "--- Performance Comparison ---"

$workload = 1..20
$heavyScript = {
    param($n)
    Start-Sleep -Milliseconds 100
    return $n * 2
}

# Sequential execution
Log-Info "Running sequentially..."
$seqStart = Get-Date
foreach ($item in $workload) {
    $null = & $heavyScript $item
}
$seqTime = (Get-Date) - $seqStart

# Parallel execution
Log-Info "Running in parallel..."
$parStart = Get-Date
$null = Invoke-CCFParallel -ScriptBlock $heavyScript -InputObjects $workload -MaxThreads 4
$parTime = (Get-Date) - $parStart

Write-Host "`nSequential: $($seqTime.TotalSeconds)s" -ForegroundColor Yellow
Write-Host "Parallel:   $($parTime.TotalSeconds)s" -ForegroundColor Green
$speedup = [math]::Round($seqTime.TotalSeconds / $parTime.TotalSeconds, 2)
Write-Host "Speedup:    ${speedup}x faster!" -ForegroundColor Cyan

Log-Header "=== Parallel Execution Demo Complete ==="
