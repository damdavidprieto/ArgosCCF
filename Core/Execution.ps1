# ArgosCCF execution engine: parallel execution with runspace pools, retries and timing.

function Invoke-CCFParallel {
    <#
    .SYNOPSIS
        Runs a script block for each input object in parallel and returns one result per object.

    .DESCRIPTION
        Runs -ScriptBlock once per input object in a pool of runspaces, up to -MaxThreads at a
        time, and returns one object per input, in input order, with Target, Output, Status
        ("Success" or "Failed"), Error, Retries, Duration (seconds) and Index.
        The script block receives the input object as its first argument and -Arguments as
        the second. It runs in a separate runspace: it cannot see your variables or functions,
        and is rebuilt from its text, so pass everything it needs as arguments.
        A failure in one object does not stop the others; with -RetryCount it is retried after
        -RetryDelayMs. -OnProgress is called in your session after each object finishes.

    .PARAMETER ScriptBlock
        Code to run for each object. Receives ($inputObject, $arguments).

    .PARAMETER InputObjects
        The objects to process.

    .PARAMETER MaxThreads
        Maximum number of objects processed at the same time. Defaults to the number of
        processors; values below 2 are raised to 2.

    .PARAMETER Arguments
        Hashtable passed to every run as the second argument.

    .PARAMETER RetryCount
        Number of extra attempts for an object whose script block throws. Defaults to 0.

    .PARAMETER RetryDelayMs
        Milliseconds to wait between attempts. Defaults to 500.

    .PARAMETER OnProgress
        Optional script block called as ($processedCount, $totalCount) after each object.

    .EXAMPLE
        Invoke-CCFParallel -InputObjects 'server1', 'server2' -ScriptBlock { param($name) Test-Connection $name -Count 1 -Quiet }

        Pings both servers at the same time and returns one result per server.

    .EXAMPLE
        $results = Invoke-CCFParallel -InputObjects (1..20) -MaxThreads 4 -RetryCount 2 -ScriptBlock {
            param($n, $config) Invoke-RestMethod "$($config.Url)/items/$n"
        } -Arguments @{ Url = 'https://api.example.com' }
        $results | Where-Object Status -EQ 'Failed'

        Fetches 20 items, four at a time with two retries each, and lists the failures.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]], [object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$InputObjects,

        [ValidateRange(1, 256)]
        [int]$MaxThreads = [Environment]::ProcessorCount,

        [hashtable]$Arguments = @{},

        [ValidateRange(0, 100)]
        [int]$RetryCount = 0,

        [ValidateRange(0, 600000)]
        [int]$RetryDelayMs = 500,

        [scriptblock]$OnProgress
    )

    $totalTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-CCFLogInfo "Inicializando motor paralelo (Hilos: $MaxThreads, Reintentos: $RetryCount)"

    if ($MaxThreads -lt 2) { $MaxThreads = 2 }

    $rsPool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
    $rsPool.Open()

    $jobs = [System.Collections.Generic.List[PSCustomObject]]::new()
    $finalResults = [System.Collections.Generic.List[PSCustomObject]]::new()
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
                        catch { Write-Verbose "OnProgress failed: $($_.Exception.Message)" }
                    }
                }
                catch {
                    Write-CCFLogError "Fallo fatal en Runspace para $($job.Target): $($_.Exception.Message)"
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
