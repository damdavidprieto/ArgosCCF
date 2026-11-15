# Writing log files: concurrent writers, rotation during a session and the file format.

BeforeAll {
    $script:manifest = Join-Path $PSScriptRoot '../../ArgosCCF.psd1'
    Import-Module $manifest -Force
    Mock -ModuleName ArgosCCF Write-Host { }
}

AfterAll {
    InModuleScope ArgosCCF {
        $script:LogsPathOverride = $null
        $script:CurrentLogFile = $null
        $script:MaxLogSizeMB = 10
        $script:MaxLogRolling = 5
    }
}

Describe 'Concurrent writers' {
    It 'keeps every entry when several runspaces write to the same file at the same time' {
        $folder = Join-Path $TestDrive 'concurrent'
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
                        Initialize-CCFLogger -Path $f -FileName 'shared.log'
                        for ($i = 0; $i -lt 100; $i++) { Write-CCFLog -Message "t$t-$i" }
                    }).AddArgument($manifest).AddArgument($folder).AddArgument($t)
                @{ PS = $ps; Handle = $ps.BeginInvoke() }
            }
            foreach ($job in $jobs) { $job.PS.EndInvoke($job.Handle); $job.PS.Dispose() }
        }
        finally { $pool.Close() }

        $lines = @(Get-Content (Join-Path $folder 'shared.log'))
        $lines.Count | Should -Be 400
        foreach ($t in 1..4) { @($lines | Where-Object { $_ -match " t$t-\d+$" }).Count | Should -Be 100 }
    }

    It 'uses one lock name per file, ignoring case on Windows' {
        InModuleScope ArgosCCF -Parameters @{ Folder = $TestDrive } {
            param($Folder)
            $a = Get-CCFFileMutexName -Path (Join-Path $Folder 'a.log')
            $a | Should -Match '^ArgosCCF-[0-9a-f]{32}$'
            Get-CCFFileMutexName -Path (Join-Path $Folder 'b.log') | Should -Not -Be $a
            if (-not ($IsLinux -or $IsMacOS)) {
                $script:CCFMutexNames.Clear()
                Get-CCFFileMutexName -Path (Join-Path $Folder 'A.LOG') | Should -Be $a
            }
        }
    }

    It 'releases the lock after each write' {
        $folder = Join-Path $TestDrive 'lock'
        Initialize-CCFLogger -Path $folder -FileName 'lock.log'
        Write-CCFLogInfo 'one entry'
        $name = InModuleScope ArgosCCF -Parameters @{ P = (Join-Path $folder 'lock.log') } { param($P) Get-CCFFileMutexName -Path $P }
        $mutex = [System.Threading.Mutex]::new($false, $name)
        try { $mutex.WaitOne(0) | Should -BeTrue; $mutex.ReleaseMutex() }
        finally { $mutex.Dispose() }
    }
}

Describe 'Rotation during a session' {
    BeforeEach {
        $folder = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $folder | Out-Null
        $big = 'x' * (1MB + 10)
    }

    It 'rotates the session file before a write once it is larger than -MaxMB' {
        Initialize-CCFLogger -Path $folder -FileName 'session.log' -MaxMB 1 -MaxRolling 3
        [System.IO.File]::WriteAllText((Join-Path $folder 'session.log'), $big)
        Write-CCFLogInfo 'after the limit'
        Join-Path $folder 'session.log.1' | Should -Exist
        (Get-Item (Join-Path $folder 'session.log.1')).Length | Should -BeGreaterThan 1MB
        @(Get-Content (Join-Path $folder 'session.log')).Count | Should -Be 1
    }

    It 'rotates category files too' {
        Initialize-CCFLogger -Path $folder -FileName 'session.log' -MaxMB 1
        [System.IO.File]::WriteAllText((Join-Path $folder 'CCF_Audit.log'), $big)
        Write-CCFAuditRecord -Action 'Test' -User 'bob'
        Join-Path $folder 'CCF_Audit.log.1' | Should -Exist
        @(Get-Content (Join-Path $folder 'CCF_Audit.log')).Count | Should -Be 1
    }

    It 'keeps at most -MaxRolling rotated files' {
        Initialize-CCFLogger -Path $folder -FileName 'session.log' -MaxMB 1 -MaxRolling 2
        foreach ($round in 1..4) {
            [System.IO.File]::WriteAllText((Join-Path $folder 'session.log'), $big)
            Write-CCFLogInfo "round $round"
        }
        @(Get-ChildItem $folder -Filter 'session.log*').Name | Sort-Object | Should -Be @('session.log', 'session.log.1', 'session.log.2')
    }

    It 'does not rotate a file below the limit' {
        Initialize-CCFLogger -Path $folder -FileName 'session.log' -MaxMB 1
        Write-CCFLogInfo 'small'
        Write-CCFLogInfo 'still small'
        Join-Path $folder 'session.log.1' | Should -Not -Exist
    }
}

Describe 'File format' {
    It 'writes UTF-8 without BOM, one entry per line' {
        $folder = Join-Path $TestDrive 'format'
        Initialize-CCFLogger -Path $folder -FileName 'format.log'
        Write-CCFLogInfo "año ñandú`nsecond line"
        $bytes = [System.IO.File]::ReadAllBytes((Join-Path $folder 'format.log'))
        ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB) | Should -BeFalse
        $lines = @([System.IO.File]::ReadAllLines((Join-Path $folder 'format.log'), [System.Text.Encoding]::UTF8))
        $lines.Count | Should -Be 1
        $lines[0] | Should -Match 'año ñandú\\nsecond line$'
    }
}
