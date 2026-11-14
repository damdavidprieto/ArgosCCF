<#
    .SYNOPSIS
    CCF Execution Engine - Parallel Computing (Optimized)
    
    .DESCRIPTION
    Proporciona capacidades de ejecución paralela utilizando RunspacePools.
    Incluye lógica de reintentos automáticos y telemetría de rendimiento.
#>

function Invoke-CCFParallel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter(Mandatory = $true)]
        [array]$InputObjects,
        
        [int]$MaxThreads = [int]$env:NUMBER_OF_PROCESSORS,
        
        [hashtable]$Arguments = @{},
        
        [int]$RetryCount = 0,
        
        [int]$RetryDelayMs = 500,

        [scriptblock]$OnProgress # Callback: param($processedCount, $totalCount)
    )
    
    $totalTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Log-Info "Inicializando motor paralelo (Hilos: $MaxThreads, Reintentos: $RetryCount)"
    
    if ($MaxThreads -lt 2) { $MaxThreads = 2 }
    
    $rsPool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
    $rsPool.Open()
    
    $jobs = New-Object System.Collections.Generic.List[PSCustomObject]
    $finalResults = New-Object System.Collections.Generic.List[PSCustomObject]
    $totalObjects = $InputObjects.Count
    $processedCount = 0

    # ScriptBlock Wrapper para Telemetría y Errores
    # The task is passed as text and rebuilt inside each runspace. A script block keeps an
    # affinity to the runspace that created it, so invoking the caller's own script block
    # from the pool marshals it back to the (busy) caller and fails intermittently on 5.1.
    $wrapper = {
        param($obj, $Params, $sbText, $tries, $delayMs)
        $sb = [scriptblock]::Create($sbText)
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $currentTry = 0
        $success = $false
        $output = $null
        $lastError = $null

        while ($currentTry -le $tries -and -not $success) {
            try {
                $output = & $sb $obj $Params
                $success = $true
            }
            catch {
                $lastError = $_.Exception.Message
                $currentTry++
                if ($currentTry -le $tries) { Start-Sleep -Milliseconds $delayMs }
            }
        }
        $timer.Stop()
        return [PSCustomObject]@{
            Output   = $output
            Duration = $timer.Elapsed.TotalSeconds
            Success  = $success
            Error    = $lastError
            Retries  = $currentTry
        }
    }
    
    try {
        $index = 0
        foreach ($obj in $InputObjects) {
            $ps = [PowerShell]::Create().AddScript($wrapper)
            $ps.RunspacePool = $rsPool
            $null = $ps.AddArgument($obj).AddArgument($Arguments).AddArgument($ScriptBlock.ToString()).AddArgument($RetryCount).AddArgument($RetryDelayMs)

            $jobs.Add([PSCustomObject]@{
                    PowerShell = $ps
                    Handle     = $ps.BeginInvoke()
                    Target     = $obj
                    Index      = $index
                })
            $index++
        }
        
        while ($jobs.Count -gt 0) {
            $done = $jobs | Where-Object { $_.Handle.IsCompleted }
            foreach ($job in $done) {
                try {
                    $res = $job.PowerShell.EndInvoke($job.Handle)
                    $finalResults.Add([PSCustomObject]@{
                            Index    = $job.Index
                            Target   = $job.Target
                            Output   = $res.Output
                            Duration = $res.Duration
                            Status   = if ($res.Success) { "Success" } else { "Failed" }
                            Retries  = $res.Retries
                            Error    = $res.Error
                        })
                    
                    # Update progress
                    $processedCount++
                    if ($null -ne $OnProgress) {
                        try {
                            & $OnProgress $processedCount $totalObjects
                        }
                        catch { }
                    }
                }
                catch {
                    # Use Write-Host if Log-Error fails for some reason
                    Write-Host "[!] Fallo fatal en Runspace para $($job.Target): $($_.Exception.Message)" -ForegroundColor Red
                }
                finally {
                    $job.PowerShell.Dispose()
                    $null = $jobs.Remove($job)
                }
            }
            if ($jobs.Count -gt 0) { Start-Sleep -Milliseconds 100 }
        }
        
        $totalTimer.Stop()
        Write-CCFLogSuccess "Paralelización finalizada en $([math]::Round($totalTimer.Elapsed.TotalSeconds, 2))s."
        # Results come back in completion order; return them in input order.
        return @($finalResults | Sort-Object Index)
    }
    finally {
        if ($null -ne $rsPool) {
            $rsPool.Close()
            $rsPool.Dispose()
        }
    }
}

