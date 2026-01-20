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
        
        [int]$RetryDelayMs = 500
    )
    
    $totalTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Log-Info "Inicializando motor paralelo (Hilos: $MaxThreads, Reintentos: $RetryCount)"
    
    if ($MaxThreads -lt 2) { $MaxThreads = 2 }
    
    $rsPool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
    $rsPool.Open()
    
    $jobs = New-Object System.Collections.Generic.List[PSCustomObject]
    $finalResults = New-Object System.Collections.Generic.List[PSCustomObject]

    # ScriptBlock Wrapper para Telemetría y Errores
    $wrapper = {
        param($obj, $args, $sb, $tries)
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $currentTry = 0
        $success = $false
        $output = $null
        $lastError = $null

        while ($currentTry -le $tries -and -not $success) {
            try {
                $output = & $sb $obj $args
                $success = $true
            }
            catch {
                $lastError = $_.Exception.Message
                $currentTry++
                if ($currentTry -le $tries) { Start-Sleep -Milliseconds 200 }
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
        foreach ($obj in $InputObjects) {
            $ps = [PowerShell]::Create().AddScript($wrapper)
            $ps.RunspacePool = $rsPool
            $ps.AddArgument($obj).AddArgument($Arguments).AddArgument($ScriptBlock).AddArgument($RetryCount)
            
            $jobs.Add([PSCustomObject]@{
                    PowerShell = $ps
                    Handle     = $ps.BeginInvoke()
                    Target     = $obj
                })
        }
        
        while ($jobs.Count -gt 0) {
            $done = $jobs | Where-Object { $_.Handle.IsCompleted }
            foreach ($job in $done) {
                try {
                    $res = $job.PowerShell.EndInvoke($job.Handle)
                    $finalResults.Add([PSCustomObject]@{
                            Target   = $job.Target
                            Output   = $res.Output
                            Duration = $res.Duration
                            Status   = if ($res.Success) { "Success" } else { "Failed" }
                            Retries  = $res.Retries
                            Error    = $res.Error
                        })
                }
                catch {
                    Log-Error "Fallo fatal en Runspace para $($job.Target)"
                }
                finally {
                    $job.PowerShell.Dispose()
                    $jobs.Remove($job) | Out-Null
                }
            }
            if ($jobs.Count -gt 0) { Start-Sleep -Milliseconds 100 }
        }
        
        $totalTimer.Stop()
        Log-Success "Paralelización finalizada en $($totalTimer.Elapsed.TotalSeconds)s."
        return $finalResults
    }
    finally {
        $rsPool.Close()
        $rsPool.Dispose()
    }
}

Export-ModuleMember -Function Invoke-CCFParallel
