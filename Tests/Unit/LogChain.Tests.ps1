# Tamper-evident logs: Initialize-CCFLogger -Chain, Test-CCFLogChain and Get-CCFLogChainHead.

BeforeAll {
    $script:manifest = Join-Path $PSScriptRoot '../../ArgosCCF.psd1'
    Import-Module $script:manifest -Force
    Mock -ModuleName ArgosCCF Write-Host { }

    function New-ChainedLog([string]$Name, [int]$Count = 3, [switch]$Json) {
        $folder = Join-Path $TestDrive $Name
        Initialize-CCFLogger -Path $folder -Chain Audit -JsonOutput:$Json
        for ($i = 1; $i -le $Count; $i++) { Write-CCFAuditRecord -Action "Change$i" -User 'tester' -Resource "item$i" }
        return Join-Path $folder 'CCF_Audit.log'
    }
}

AfterAll {
    InModuleScope ArgosCCF {
        $script:LogsPathOverride = $null
        $script:CurrentLogFile = $null
        $script:CCFChainCategories = @()
        $script:JsonOutput = $false
        $script:MaxLogSizeMB = 10
        $script:MaxLogRolling = 5
    }
}

Describe 'Chained logs' {
    It 'adds a hash to every line of a chained category, and the chain checks out' {
        $log = New-ChainedLog 'plain'
        $lines = @(Get-Content $log)
        $lines.Count | Should -Be 3
        $lines | ForEach-Object { $_ | Should -Match ' #chain=[0-9a-f]{64}$' }
        $r = Test-CCFLogChain -Path $log
        $r.Valid | Should -BeTrue
        $r.Entries | Should -Be 3
        $r.LastHash | Should -Be (Get-CCFLogChainHead -Path $log)
    }

    It 'does not chain other categories' {
        $log = New-ChainedLog 'other' 1
        Write-CCFLog -Message 'not chained' -Category 'Errors'
        Get-Content (Join-Path (Split-Path $log) 'CCF_Errors.log') | Should -Not -Match '#chain='
    }

    It 'finds a changed line' {
        $log = New-ChainedLog 'changed'
        $lines = @(Get-Content $log)
        $lines[1] = $lines[1].Replace('Change2', 'Change9')
        Set-Content -Path $log -Value $lines
        $r = Test-CCFLogChain -Path $log
        $r.Valid | Should -BeFalse
        $r.BrokenAt | Should -Match ':2$'
    }

    It 'finds a deleted line in the middle and a line added without a hash' {
        $log = New-ChainedLog 'deleted'
        $lines = @(Get-Content $log)
        Set-Content -Path $log -Value @($lines[0], $lines[2])
        (Test-CCFLogChain -Path $log).Valid | Should -BeFalse
        Set-Content -Path $log -Value (@($lines) + '[2026-01-01T00:00:00.000Z] [INFO] [Audit] [AUDIT] fake')
        (Test-CCFLogChain -Path $log).Reason | Should -Match 'without a chain hash'
    }

    It 'finds deleted last lines when given the head saved earlier' {
        $log = New-ChainedLog 'tail'
        $head = Get-CCFLogChainHead -Path $log
        $lines = @(Get-Content $log)
        Set-Content -Path $log -Value $lines[0..1]
        (Test-CCFLogChain -Path $log).Valid | Should -BeTrue
        $r = Test-CCFLogChain -Path $log -ExpectedLastHash $head
        $r.Valid | Should -BeFalse
        $r.Reason | Should -Match 'deleted'
        (Test-CCFLogChain -Path $log -ExpectedLastHash @((Get-CCFLogChainHead -Path $log), $head)).Valid | Should -BeFalse
        (Test-CCFLogChain -Path $log -ExpectedLastHash @((Get-CCFLogChainHead -Path $log))).Valid | Should -BeTrue
    }

    It 'continues the chain across rotation' {
        $folder = Join-Path $TestDrive 'rotated'
        Initialize-CCFLogger -Path $folder -Chain Audit -MaxMB 1
        Write-CCFAuditRecord -Action 'Before' -User 'tester'
        $log = Join-Path $folder 'CCF_Audit.log'
        InModuleScope ArgosCCF -Parameters @{ Log = $log } { param($Log) Invoke-CCFLogRotation -Path $Log -MaxMB 0 -MaxRolling 3 }
        Write-CCFAuditRecord -Action 'After' -User 'tester'
        Test-Path "$log.1" | Should -BeTrue
        $r = Test-CCFLogChain -Path $log -IncludeRotated
        $r.Valid | Should -BeTrue
        $r.Entries | Should -Be 2
    }

    It 'keeps JSON lines valid JSON, with the hash in a Chain property' {
        $log = New-ChainedLog 'json' 2 -Json
        foreach ($line in Get-Content $log) {
            $o = $line | ConvertFrom-Json
            $o.Chain | Should -Match '^[0-9a-f]{64}$'
        }
        (Test-CCFLogChain -Path $log).Valid | Should -BeTrue
    }

    It 'chains in write order when several runspaces write at the same time' {
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
                        Initialize-CCFLogger -Path $f -Chain Audit
                        for ($i = 0; $i -lt 25; $i++) { Write-CCFAuditRecord -Action "t$t-$i" -User 'tester' }
                    }).AddArgument($script:manifest).AddArgument($folder).AddArgument($t)
                @{ PS = $ps; Handle = $ps.BeginInvoke() }
            }
            foreach ($job in $jobs) { $job.PS.EndInvoke($job.Handle); $job.PS.Dispose() }
        }
        finally { $pool.Close() }
        $r = Test-CCFLogChain -Path (Join-Path $folder 'CCF_Audit.log')
        $r.Valid | Should -BeTrue
        $r.Entries | Should -Be 100
    }
}
