# Background writing: Initialize-CCFLogger -Background, Get-/Wait-/Stop-CCFLogWriter.

BeforeAll {
    $script:manifest = Join-Path $PSScriptRoot '../../ArgosCCF.psd1'
    Import-Module $manifest -Force
    Mock -ModuleName ArgosCCF Write-Host { }

    function script:Get-LogLine([string]$Path) {
        if (-not (Test-Path -LiteralPath $Path)) { return , [string[]]@() }
        return , [System.IO.File]::ReadAllLines($Path)
    }
}

AfterAll {
    Stop-CCFLogWriter
    InModuleScope ArgosCCF {
        $script:CCFPaths.LogsPathOverride = $null
        $script:CCFLog.CurrentLogFile = $null
        $script:CCFLog.MaxLogSizeMB = 10
        $script:CCFLog.MaxLogRolling = 5
    }
}

Describe 'Background writer' {
    BeforeEach {
        $folder = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $file = Join-Path $folder 'bg.log'
    }

    AfterEach { Stop-CCFLogWriter -WarningAction SilentlyContinue }

    It 'is off by default' {
        Initialize-CCFLogger -Path $folder -FileName 'bg.log'
        $state = Get-CCFLogWriter
        $state.Mode | Should -Be 'Direct'
        $state.Running | Should -BeFalse
        $state.Queued | Should -Be 0
    }

    It 'writes every entry, in order, once the queue is waited for' {
        Initialize-CCFLogger -Path $folder -FileName 'bg.log' -Background
        (Get-CCFLogWriter).Mode | Should -Be 'Background'
        for ($i = 0; $i -lt 500; $i++) { Write-CCFLogInfo "entry $i" }
        Wait-CCFLogWriter
        $lines = Get-LogLine $file
        $lines.Count | Should -Be 500
        for ($i = 0; $i -lt 500; $i++) { $lines[$i] | Should -Match " entry $i$" }
        $state = Get-CCFLogWriter
        $state.Written | Should -Be 500
        $state.Failed | Should -Be 0
        $state.Queued | Should -Be 0
    }

    It 'still redacts secrets before they are queued' {
        Initialize-CCFLogger -Path $folder -FileName 'bg.log' -Background
        Write-CCFLogInfo 'password=Sup3rS3cretValue!'
        Wait-CCFLogWriter
        (Get-LogLine $file) -join "`n" | Should -Not -Match 'Sup3rS3cretValue'
    }

    It 'waits for ERROR, CRITICAL, -NoBuffer, Security and Audit entries' {
        Initialize-CCFLogger -Path $folder -FileName 'bg.log' -Background
        Write-CCFLogError 'an error'
        (Get-LogLine $file)[-1] | Should -Match 'an error$'
        Write-CCFLogCritical 'a critical'
        (Get-LogLine $file)[-1] | Should -Match 'a critical$'
        Write-CCFLog -Message 'not buffered' -NoBuffer
        (Get-LogLine $file)[-1] | Should -Match 'not buffered$'
        Write-CCFSecurityRecord -Type 'Probe' -Source 'test'
        (Get-LogLine (Join-Path $folder 'CCF_Security.log'))[-1] | Should -Match 'Probe from test'
        Write-CCFAuditRecord -Action 'Delete' -User 'bob'
        (Get-LogLine (Join-Path $folder 'CCF_Audit.log'))[-1] | Should -Match 'bob Delete'
    }

    It 'rotates files written from the background' {
        Initialize-CCFLogger -Path $folder -FileName 'bg.log' -MaxMB 1 -Background
        [System.IO.File]::WriteAllText($file, 'x' * (1MB + 10))
        Write-CCFLogInfo 'after the limit'
        Wait-CCFLogWriter
        "$file.1" | Should -Exist
        (Get-LogLine $file).Count | Should -Be 1
    }

    It 'keeps every entry when several runspaces write in the background to the same file' {
        $pool = [runspacefactory]::CreateRunspacePool(1, 4)
        $pool.Open()
        try {
            $jobs = foreach ($t in 1..4) {
                $ps = [powershell]::Create()
                $ps.RunspacePool = $pool
                $null = $ps.AddScript({
                        param($m, $f, $t)
                        Import-Module $m -Force 6>$null
                        Register-CCFLogProvider -ProviderScript { } 6>$null
                        Initialize-CCFLogger -Path $f -FileName 'bg.log' -Background
                        for ($i = 0; $i -lt 250; $i++) { Write-CCFLog -Message "t$t-$i" }
                        Stop-CCFLogWriter
                    }).AddArgument($manifest).AddArgument($folder).AddArgument($t)
                @{ PS = $ps; Handle = $ps.BeginInvoke() }
            }
            foreach ($job in $jobs) { $job.PS.EndInvoke($job.Handle); $job.PS.Dispose() }
        }
        finally { $pool.Close() }

        $lines = Get-LogLine $file
        # Each runspace logs "Log provider registered." to the session file too.
        @($lines | Where-Object { $_ -match ' t\d-\d+$' }).Count | Should -Be 1000
        foreach ($t in 1..4) {
            $mine = @($lines | Where-Object { $_ -match " t$t-(\d+)$" } | ForEach-Object { [int]($_ -replace '.* t\d-', '') })
            $mine.Count | Should -Be 250
            ($mine -join ',') | Should -Be ((0..249) -join ',')
        }
    }

    It 'counts entries it cannot write and reports them' {
        Initialize-CCFLogger -Path $folder -FileName 'bg.log' -Background
        # A folder where the file should be: every write fails.
        $null = New-Item -ItemType Directory -Path $file -Force
        Write-CCFLogInfo 'cannot be written'
        Wait-CCFLogWriter
        $state = Get-CCFLogWriter
        $state.Failed | Should -Be 1
        $state.LastError | Should -Match 'bg\.log'
        (Test-CCFHealth).Status | Should -Be 'DEGRADED'
        Stop-CCFLogWriter -WarningVariable warned -WarningAction SilentlyContinue
        $warned | Should -Match 'could not be written'
    }

    It 'writes the queue and returns to direct writing when stopped' {
        Initialize-CCFLogger -Path $folder -FileName 'bg.log' -Background
        for ($i = 0; $i -lt 100; $i++) { Write-CCFLogInfo "entry $i" }
        Stop-CCFLogWriter
        (Get-LogLine $file).Count | Should -Be 100
        (Get-CCFLogWriter).Mode | Should -Be 'Direct'
        Write-CCFLogInfo 'direct again'
        (Get-LogLine $file)[-1] | Should -Match 'direct again$'
    }

    It 'stops the background writer when the logger is initialized again without -Background' {
        Initialize-CCFLogger -Path $folder -FileName 'bg.log' -Background
        for ($i = 0; $i -lt 50; $i++) { Write-CCFLogInfo "entry $i" }
        Initialize-CCFLogger -Path $folder -FileName 'second.log'
        (Get-CCFLogWriter).Mode | Should -Be 'Direct'
        (Get-LogLine $file).Count | Should -Be 50
    }

    It 'writes the queue when the module is imported again' {
        Initialize-CCFLogger -Path $folder -FileName 'bg.log' -Background
        for ($i = 0; $i -lt 200; $i++) { Write-CCFLogInfo "entry $i" }
        Import-Module $manifest -Force
        Mock -ModuleName ArgosCCF Write-Host { }
        (Get-LogLine $file).Count | Should -Be 200
    }

    It 'returns at once when there is no background writer' {
        Stop-CCFLogWriter
        { Wait-CCFLogWriter -TimeoutSeconds 0; Stop-CCFLogWriter } | Should -Not -Throw
    }
}

Describe 'Background writer at exit' {
    It 'writes the queue and keeps the exit code when PowerShell exits' {
        $exe = if ($PSVersionTable.PSEdition -eq 'Core') { (Get-Process -Id $PID).Path } else { 'powershell.exe' }
        $folder = Join-Path $TestDrive 'exit'
        $command = "Import-Module '$manifest' 6>`$null; Register-CCFLogProvider -ProviderScript { } 6>`$null; " +
        "Initialize-CCFLogger -Path '$folder' -FileName 'exit.log' -Background; " +
        "for (`$i = 0; `$i -lt 1000; `$i++) { Write-CCFLog -Message ('entry ' + `$i) }; exit 3"
        & $exe -NoProfile -NonInteractive -Command $command
        $LASTEXITCODE | Should -Be 3
        @((Get-LogLine (Join-Path $folder 'exit.log')) | Where-Object { $_ -match ' entry \d+$' }).Count | Should -Be 1000
    }
}
