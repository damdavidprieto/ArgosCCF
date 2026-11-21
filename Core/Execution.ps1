# ArgosCCF execution engine: parallel execution with runspace pools, retries and timing.
# Deprecated: removed in 2.0.0; use ForEach-Object -Parallel (PowerShell 7) or ThreadJob.

function Invoke-CCFParallel {
    <#
    .SYNOPSIS
        Runs a script block for each input object in parallel and returns one result per object.

    .DESCRIPTION
        Deprecated: parallel execution will be removed from ArgosCCF in 2.0.0, which keeps only
        logging and redaction. It keeps working in 1.x. Use ForEach-Object -Parallel (PowerShell 7)
        or the ThreadJob module instead.
        Runs -ScriptBlock once per input object in a pool of runspaces, up to -MaxThreads at a
        time, and returns one object per input, in input order, with Target, Output, Status
        ("Success" or "Failed"), Error, Retries, Duration (seconds) and Index.
        The script block receives the input object as its first argument and -Arguments as
        the second. It runs in a separate runspace: it cannot see your variables or functions,
        and is rebuilt from its text, so pass everything it needs as arguments.
        A failure in one object does not stop the others; with -RetryCount it is retried after
        -RetryDelayMs. Errors written with Write-Error count as failures too (the script block
        runs with $ErrorActionPreference = 'Stop'). Retries is the number of retries made.
        -OnProgress is called in your session after each object finishes.

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
    if ($MaxThreads -lt 2) { $MaxThreads = 2 }
    Write-CCFLogInfo "Starting parallel execution (threads: $MaxThreads, retries: $RetryCount)"

    $rsPool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
    $rsPool.Open()

    $jobs = [System.Collections.Generic.List[PSCustomObject]]::new()
    $finalResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $totalObjects = $InputObjects.Count
    $processedCount = 0

    # Wrapper that times each run and handles retries and errors
    # The task is passed as text and rebuilt inside each runspace. A script block keeps an
    # affinity to the runspace that created it, so invoking the caller's own script block
    # from the pool marshals it back to the (busy) caller and fails intermittently on 5.1.
    $wrapper = {
        param($obj, $Params, $sbText, $tries, $delayMs)
        $sb = [scriptblock]::Create($sbText)
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $success = $false
        $output = $null
        $lastError = $null

        # Errors written with Write-Error (non-terminating) also count as a failure: otherwise a
        # script block that only reports errors would be returned as Success.
        $ErrorActionPreference = 'Stop'
        $attempt = 0
        while ($attempt -le $tries -and -not $success) {
            if ($attempt -gt 0) { Start-Sleep -Milliseconds $delayMs }
            try {
                $output = & $sb $obj $Params
                $success = $true
            }
            catch {
                $lastError = $_.Exception.Message
                $attempt++
            }
        }
        $timer.Stop()
        return [PSCustomObject]@{
            Output   = $output
            Duration = $timer.Elapsed.TotalSeconds
            Success  = $success
            Error    = $lastError
            # Retries made: failed attempts before the success, or every retry when it never succeeded.
            Retries  = if ($success) { $attempt } else { $attempt - 1 }
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
                    # The object still gets a result: the output has one entry per input.
                    Write-CCFLogError "Runspace failed for $($job.Target): $($_.Exception.Message)"
                    $finalResults.Add([PSCustomObject]@{
                            Index    = $job.Index
                            Target   = $job.Target
                            Output   = $null
                            Duration = 0
                            Status   = 'Failed'
                            Retries  = 0
                            Error    = $_.Exception.Message
                        })
                    $processedCount++
                }
                finally {
                    $job.PowerShell.Dispose()
                    $null = $jobs.Remove($job)
                }
            }
            if ($jobs.Count -gt 0) { Start-Sleep -Milliseconds 100 }
        }

        $totalTimer.Stop()
        Write-CCFLogSuccess "Parallel execution finished in $([math]::Round($totalTimer.Elapsed.TotalSeconds, 2))s."
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
