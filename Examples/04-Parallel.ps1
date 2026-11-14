# Parallel execution with retries and progress.
# Run from the repository: .\Examples\04-Parallel.ps1

Import-Module (Join-Path $PSScriptRoot '..\ArgosCCF.psd1') -Force

# Each run receives the input object and the -Arguments hashtable. It runs in its own
# runspace, so it cannot see variables from this script: pass what it needs as arguments.
$results = Invoke-CCFParallel -InputObjects (1..8) -MaxThreads 4 -RetryCount 1 -RetryDelayMs 100 -Arguments @{ Factor = 10 } -ScriptBlock {
    param($n, $config)
    Start-Sleep -Milliseconds (50 * $n)
    if ($n -eq 5) { throw "Item $n failed" }
    $n * $config.Factor
} -OnProgress {
    param($done, $total)
    Write-Progress -Activity 'Processing' -Status "$done of $total" -PercentComplete ($done / $total * 100)
}
Write-Progress -Activity 'Processing' -Completed

# One result per input, in input order.
$results | Format-Table Target, Status, Output, Retries, @{ Name = 'Seconds'; Expression = { [math]::Round($_.Duration, 2) } } -AutoSize | Out-Host

$failed = @($results | Where-Object Status -EQ 'Failed')
Write-CCFLogInfo "$($results.Count - $failed.Count) succeeded, $($failed.Count) failed: $($failed.Error -join '; ')"
