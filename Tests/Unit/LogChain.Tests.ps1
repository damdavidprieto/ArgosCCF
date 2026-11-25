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
        $script:CCFChainId = ''
        $script:CCFStrict = $false
        $script:CCFChainAnchor = $null
        $script:CCFChainAnchorSeconds = 0
        $script:CCFChainAnchorFailures = 0
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

Describe 'Chain identifier' {
    BeforeAll {
        function Add-Entry([string]$Folder, [string]$Id, [switch]$Json) {
            $extra = @{}
            if ($Id) { $extra.ChainId = $Id }
            Initialize-CCFLogger -Path $Folder -Chain Audit -JsonOutput:$Json @extra
            Write-CCFAuditRecord -Action 'Change' -User 'tester' -Resource 'item'
            return Join-Path $Folder 'CCF_Audit.log'
        }
    }

    It 'is part of every line and can be checked (JSON: <Json>)' -TestCases @(@{ Json = $false }, @{ Json = $true }) {
        $folder = Join-Path $TestDrive "id-$Json"
        $null = Add-Entry $folder 'copy-a' -Json:$Json
        $log = Add-Entry $folder 'copy-a' -Json:$Json
        $r = Test-CCFLogChain -Path $log -ChainId 'copy-a' -IncludeRotated
        $r.Valid | Should -BeTrue
        $r.ChainId | Should -Be 'copy-a'
        (Test-CCFLogChain -Path $log).Valid | Should -BeTrue
        (Test-CCFLogChain -Path $log -ChainId 'copy-b').Valid | Should -BeFalse
        $head = Get-CCFLogChainHead -Path $log -AsObject
        $head.ChainId | Should -Be 'copy-a'
        $head.Hash | Should -Be (Get-CCFLogChainHead -Path $log)
        if ($Json) { (Get-Content $log | Select-Object -Last 1 | ConvertFrom-Json).ChainId | Should -Be 'copy-a' }
    }

    It 'finds a line of another copy, and one without identifier after it starts' {
        $folder = Join-Path $TestDrive 'mixed'
        $null = Add-Entry $folder 'copy-a'
        $log = Add-Entry $folder 'copy-b'
        (Test-CCFLogChain -Path $log -ChainId 'copy-a').BrokenAt | Should -Match ':2$'
        $folder = Join-Path $TestDrive 'none-after'
        $null = Add-Entry $folder 'copy-a'
        $log = Add-Entry $folder ''
        (Test-CCFLogChain -Path $log -ChainId 'copy-a').BrokenAt | Should -Match ':2$'
    }

    It 'accepts lines from before the identifier, but not a log without any' {
        $folder = Join-Path $TestDrive 'upgrade'
        $log = Add-Entry $folder ''
        (Test-CCFLogChain -Path $log -ChainId 'copy-a').Valid | Should -BeFalse
        $null = Add-Entry $folder 'copy-a'
        (Test-CCFLogChain -Path $log -ChainId 'copy-a' -IncludeRotated).Valid | Should -BeTrue
    }

    It 'cannot be changed without breaking the chain, and refuses unsafe identifiers' {
        $folder = Join-Path $TestDrive 'edit'
        $null = Add-Entry $folder 'copy-a'
        $log = Add-Entry $folder 'copy-a'
        Set-Content -Path $log -Value @(Get-Content $log | ForEach-Object { $_.Replace('#id=copy-a', '#id=copy-b') })
        (Test-CCFLogChain -Path $log -ChainId 'copy-b' -IncludeRotated).Valid | Should -BeFalse
        { Initialize-CCFLogger -Path $folder -ChainId 'a b' } | Should -Throw
    }
}

Describe 'Rotation of a chained log' {
    BeforeEach {
        $script:folder = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        Initialize-CCFLogger -Path $folder -Chain Audit -MaxMB 1 -MaxRolling 2
        $script:log = Join-Path $folder 'CCF_Audit.log'
        $script:pad = 'x' * 900
    }

    It 'keeps the chain valid after the oldest copy is deleted, and drops only the hashes saved before it' {
        $saved = @()
        for ($i = 1; $i -le 3600; $i++) {
            Write-CCFAuditRecord -Action "Change$i" -User 'tester' -Resource "item $pad"
            if ($i % 300 -eq 0) { $saved += [pscustomobject]@{ Hash = (Get-CCFLogChainHead -Path $log); Time = [datetime]::UtcNow } }
        }
        Test-Path "$log.3" | Should -BeFalse
        @(Select-String -Path "$log*" -Pattern '\[CHAIN\] Archived').Count | Should -BeGreaterThan 0
        $r = Test-CCFLogChain -Path $log -IncludeRotated -ExpectedLastHash $saved
        $r.Valid | Should -BeTrue
        $r.ArchivedUntil | Should -Not -BeNullOrEmpty
        $r.MissingHashes.Count | Should -Be 0
        # Without the time, a hash of a deleted copy is still reported.
        (Test-CCFLogChain -Path $log -IncludeRotated -ExpectedLastHash $saved[0].Hash).Valid | Should -BeFalse
        # The last hash, saved after the deletion, must be there.
        $gone = [pscustomobject]@{ Hash = ('ab' * 32); Time = [datetime]::UtcNow }
        (Test-CCFLogChain -Path $log -IncludeRotated -ExpectedLastHash $gone).Valid | Should -BeFalse
    }

    It 'still finds a changed line in a rotated copy' {
        for ($i = 1; $i -le 2500; $i++) { Write-CCFAuditRecord -Action "Change$i" -User 'tester' -Resource "item $pad" }
        $lines = @(Get-Content "$log.1")
        $lines[5] = $lines[5].Replace('Change', 'Cambio')
        Set-Content -Path "$log.1" -Value $lines
        (Test-CCFLogChain -Path $log -IncludeRotated).Valid | Should -BeFalse
    }

    It 'does not accept an archive line that does not match the copy left' {
        for ($i = 1; $i -le 3600; $i++) { Write-CCFAuditRecord -Action "Change$i" -User 'tester' -Resource "item $pad" }
        $oldest = @(Get-ChildItem "$log.*" | Sort-Object Name -Descending)[0].FullName
        $lines = @(Get-Content $oldest)
        Set-Content -Path $oldest -Value $lines[1..($lines.Count - 1)]
        (Test-CCFLogChain -Path $log -IncludeRotated).Valid | Should -BeFalse
    }
}

Describe 'Chain anchors and strict writes' {
    AfterEach {
        Register-CCFChainAnchor
        InModuleScope ArgosCCF { $script:CCFChainAnchorFailures = 0; $script:CCFStrict = $false }
    }

    It 'passes every new head, with the identifier, and the last one is the head of the log' {
        $folder = Join-Path $TestDrive 'anchor'
        Initialize-CCFLogger -Path $folder -Chain Audit, Vigilancia -ChainId 'copy-a'
        $got = [System.Collections.Generic.List[object]]::new()
        Register-CCFChainAnchor -ScriptBlock { param($a) $got.Add($a) }.GetNewClosure()
        Write-CCFAuditRecord -Action 'A' -User 'u'
        Write-CCFLog -Message 'vigilancia' -Category 'Vigilancia'
        Write-CCFLog -Message 'not chained' -Category 'Errors'
        $got.Count | Should -Be 2
        $got[0].Category | Should -Be 'Audit'
        $got[0].ChainId | Should -Be 'copy-a'
        $got[0].Hash | Should -Be (Get-CCFLogChainHead -Path (Join-Path $folder 'CCF_Audit.log'))
        $got[1].Hash | Should -Be (Get-CCFLogChainHead -Path (Join-Path $folder 'CCF_Vigilancia.log'))
        (Test-CCFLogChain -Path (Join-Path $folder 'CCF_Audit.log') -ExpectedLastHash $got[0]).Valid | Should -BeTrue
    }

    It 'skips heads within -MinimumSeconds, and counts failures without stopping the log' {
        $folder = Join-Path $TestDrive 'anchor2'
        Initialize-CCFLogger -Path $folder -Chain Audit
        $script:count = 0
        Register-CCFChainAnchor -MinimumSeconds 3600 -ScriptBlock { $script:count++ }
        1..3 | ForEach-Object { Write-CCFAuditRecord -Action "A$_" -User 'u' }
        $script:count | Should -Be 1
        Register-CCFChainAnchor -ScriptBlock { throw 'down' }
        Write-CCFAuditRecord -Action 'B' -User 'u'
        @(Get-Content (Join-Path $folder 'CCF_Audit.log')).Count | Should -Be 4
        $check = (Test-CCFHealth).Checks | Where-Object { $_.Target -eq 'ChainAnchor' }
        $check.Pass | Should -BeFalse
        $check.Failures | Should -Be 1
    }

    It 'throws when a strict entry cannot be written, and only warns otherwise' {
        $folder = Join-Path $TestDrive 'strict'
        Initialize-CCFLogger -Path $folder -Chain Audit
        $locked = Join-Path $folder 'CCF_Audit.log'
        $stream = [System.IO.File]::Open($locked, 'OpenOrCreate', 'ReadWrite', 'None')
        try {
            { Write-CCFAuditRecord -Action 'A' -User 'u' -WarningAction SilentlyContinue } | Should -Not -Throw
            { Write-CCFAuditRecord -Action 'A' -User 'u' -Strict } | Should -Throw '*was not saved*'
            Initialize-CCFLogger -Path $folder -Chain Audit -Strict
            { Write-CCFAuditRecord -Action 'A' -User 'u' } | Should -Throw '*was not saved*'
            { Write-CCFLog -Message 'normal' -Category 'Other' } | Should -Not -Throw
        }
        finally { $stream.Dispose() }
    }
}
