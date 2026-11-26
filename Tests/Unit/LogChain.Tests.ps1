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
    BeforeAll {
        # 1 MB per file and 2 copies: 16 lines of 300 KB delete the oldest copy twice. Built once, copied for each test.
        $script:template = Join-Path $TestDrive 'rotated'
        $null = New-Item -ItemType Directory -Path $template
        $script:saved = @(InModuleScope ArgosCCF -Parameters @{ Log = (Join-Path $template 'CCF_Audit.log') } {
                param($Log)
                $pad = 'x' * 300000
                foreach ($i in 1..16) {
                    $line = '[{0}] [INFO] [Audit] [AUDIT] Change{1} {2}' -f [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'), $i, $pad
                    $hash = Add-CCFLogText -Path $Log -Text ($line + [Environment]::NewLine) -MaxMB 1 -MaxRolling 2 -Chain
                    [pscustomobject]@{ Hash = $hash; Time = [datetime]::UtcNow }
                }
            })
    }

    BeforeEach {
        $folder = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        Copy-Item -Path $template -Destination $folder -Recurse
        $script:log = Join-Path $folder 'CCF_Audit.log'
    }

    It 'keeps the chain valid after the oldest copy is deleted, and drops only the hashes saved before it' {
        Test-Path "$log.3" | Should -BeFalse
        @(Select-String -Path "$log*" -Pattern '\[CHAIN\] Archived').Count | Should -BeGreaterThan 0
        $r = Test-CCFLogChain -Path $log -IncludeRotated -ExpectedLastHash $saved
        $r.Valid | Should -BeTrue
        $r.ArchivedUntil | Should -Not -BeNullOrEmpty
        $r.MissingHashes.Count | Should -Be 0
        # The last hash of the newest deleted copy is accepted even without its time: the archive line records it.
        $archived = [regex]::Match((Get-Content $log -Raw), 'last hash ([0-9a-f]{64})').Groups[1].Value
        $archived | Should -Not -BeNullOrEmpty
        (Test-CCFLogChain -Path $log -IncludeRotated -ExpectedLastHash $archived).Valid | Should -BeTrue
        # A hash saved within the millisecond of the last deleted line goes with that copy; a millisecond later, not.
        $same = [pscustomobject]@{ Hash = ('ab' * 32); Time = $r.ArchivedUntil.AddTicks(5000) }
        (Test-CCFLogChain -Path $log -IncludeRotated -ExpectedLastHash $same).Valid | Should -BeTrue
        $later = [pscustomobject]@{ Hash = ('ab' * 32); Time = $r.ArchivedUntil.AddMilliseconds(1) }
        (Test-CCFLogChain -Path $log -IncludeRotated -ExpectedLastHash $later).Valid | Should -BeFalse
        # Without the time, any other hash of a deleted copy is still reported.
        (Test-CCFLogChain -Path $log -IncludeRotated -ExpectedLastHash $saved[0].Hash).Valid | Should -BeFalse
        # A hash saved after the deletion must be there.
        $gone = [pscustomobject]@{ Hash = ('ab' * 32); Time = [datetime]::UtcNow }
        (Test-CCFLogChain -Path $log -IncludeRotated -ExpectedLastHash $gone).Valid | Should -BeFalse
    }

    It 'still finds a changed line in a rotated copy' {
        $lines = @(Get-Content "$log.1")
        $lines[1] = $lines[1].Replace('Change', 'Cambio')
        Set-Content -Path "$log.1" -Value $lines
        (Test-CCFLogChain -Path $log -IncludeRotated).Valid | Should -BeFalse
    }

    It 'ignores archive words inside the message of another entry' {
        $fake = 'cd' * 32
        Initialize-CCFLogger -Path (Split-Path $log) -Chain Audit
        Write-CCFAuditRecord -Action "[CHAIN] Archived x: 1 lines up to 2099-01-01T00:00:00.000Z, last hash $fake" -User 'u'
        $r = Test-CCFLogChain -Path $log -IncludeRotated -ExpectedLastHash $fake
        $r.Valid | Should -BeFalse
        $r.ArchivedUntil | Should -BeLessThan ([datetime]'2090-01-01')
    }

    It 'does not accept an archive line that does not match the copy left' {
        $lines = @(Get-Content "$log.2")
        Set-Content -Path "$log.2" -Value $lines[1..($lines.Count - 1)]
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

Describe 'Remove-CCFOldLog on a chained log' {
    BeforeAll {
        function New-RotatedLog([string]$Folder) {
            $null = New-Item -ItemType Directory -Path $Folder -Force
            InModuleScope ArgosCCF -Parameters @{ Log = (Join-Path $Folder 'CCF_Audit.log') } {
                param($Log)
                $pad = 'x' * 300000
                # A file rotates once it reaches 1 MB, so 4 lines each: 24 lines leave the current file and .1 to .5.
                foreach ($i in 1..24) {
                    $line = '[{0}] [INFO] [Audit] [AUDIT] Change{1} {2}' -f [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'), $i, $pad
                    $null = Add-CCFLogText -Path $Log -Text ($line + [Environment]::NewLine) -MaxMB 1 -MaxRolling 5 -Chain
                }
            }
            return Join-Path $Folder 'CCF_Audit.log'
        }
    }

    It 'deletes only the oldest copies in a row, never the current file, and the chain still checks out' {
        $folder = Join-Path $TestDrive 'retention'
        $log = New-RotatedLog $folder
        Initialize-CCFLogger -Path $folder -Chain Audit
        $plain = Join-Path $folder 'Other.log'
        Set-Content -Path $plain -Value 'old'
        foreach ($f in "$log.5", "$log.4", "$log.2", $log, $plain) { (Get-Item $f).LastWriteTime = (Get-Date).AddDays(-60) }
        $removed = @(Remove-CCFOldLog -DaysToKeep 30)
        ($removed | Sort-Object) -join ',' | Should -Be 'CCF_Audit.log.4,CCF_Audit.log.5,Other.log'
        foreach ($f in $log, "$log.1", "$log.2", "$log.3") { $f | Should -Exist }
        @(Select-String -Path $log -Pattern '\[CHAIN\] Archived CCF_Audit\.log\.[45]:').Count | Should -Be 2
        (Test-CCFLogChain -Path $log -IncludeRotated).Valid | Should -BeTrue
    }

    It 'deletes nothing of a chained log with -WhatIf' {
        $folder = Join-Path $TestDrive 'whatif'
        $log = New-RotatedLog $folder
        Initialize-CCFLogger -Path $folder -Chain Audit
        (Get-Item "$log.5").LastWriteTime = (Get-Date).AddDays(-60)
        $null = Remove-CCFOldLog -DaysToKeep 30 -WhatIf
        "$log.5" | Should -Exist
        @(Select-String -Path $log -Pattern '\[CHAIN\] Archived').Count | Should -Be 0
    }
}

Describe 'Anchors in the event log' {
    It 'writes and reads back an anchor message' {
        $back = InModuleScope ArgosCCF {
            $a = [pscustomobject]@{ Path = 'C:\logs\CCF_Audit.log'; Category = 'Audit'; Hash = ('ab' * 32); ChainId = 'copy-a'; Time = [datetime]::UtcNow }
            $text = ConvertTo-CCFAnchorMessage -Anchor $a
            [pscustomobject]@{ Text = $text; Back = ConvertFrom-CCFAnchorMessage -Message $text -Time ([datetime]'2026-11-26T10:00:00Z'); Other = ConvertFrom-CCFAnchorMessage -Message 'something else' -Time (Get-Date) }
        }
        $back.Text | Should -Be "ArgosCCF anchor v1 Category=Audit ChainId=copy-a Hash=$('ab' * 32) File=CCF_Audit.log"
        $back.Back.Hash | Should -Be ('ab' * 32)
        $back.Back.ChainId | Should -Be 'copy-a'
        $back.Back.File | Should -Be 'CCF_Audit.log'
        $back.Other | Should -BeNullOrEmpty
    }

    It 'passes every head to the event log writer, and filters what it reads back' -Skip:($IsLinux -or $IsMacOS) {
        $folder = Join-Path $TestDrive 'eventlog'
        Initialize-CCFLogger -Path $folder -Chain Audit -ChainId 'copy-a'
        # The mock runs outside the module: what it receives goes to a file.
        Mock -ModuleName ArgosCCF Write-CCFEventLogEntry { Add-Content -Path (Join-Path $TestDrive 'anchors.txt') -Value ("{0}|{1}|{2}" -f $Source, $EventId, $Message); $true }
        Register-CCFChainAnchor -EventLogSource 'ArgosCCF Tests' -EventId 1234
        Write-CCFAuditRecord -Action 'A' -User 'u'
        Write-CCFAuditRecord -Action 'B' -User 'u'
        $written = @(Get-Content (Join-Path $TestDrive 'anchors.txt') | ForEach-Object { $s, $i, $m = $_ -split '\|', 3; [pscustomobject]@{ Source = $s; Id = [int]$i; Message = $m } })
        $written.Count | Should -Be 2
        $written[0].Source | Should -Be 'ArgosCCF Tests'
        $written[0].Id | Should -Be 1234
        $log = Join-Path $folder 'CCF_Audit.log'
        $written[1].Message | Should -Match ([regex]::Escape((Get-CCFLogChainHead -Path $log)))
        $events = @($written | ForEach-Object { [pscustomobject]@{ Properties = @([pscustomobject]@{ Value = $_.Message }); TimeCreated = Get-Date } })
        $events += [pscustomobject]@{ Properties = @([pscustomobject]@{ Value = 'not an anchor' }); TimeCreated = Get-Date }
        Mock -ModuleName ArgosCCF Get-WinEvent { $events }.GetNewClosure()
        $anchors = @(Get-CCFChainAnchor -EventLogSource 'ArgosCCF Tests' -EventId 1234 -Category Audit -ChainId 'copy-a')
        $anchors.Count | Should -Be 2
        (Test-CCFLogChain -Path $log -ExpectedLastHash $anchors).ExternalHashes | Should -Be 2
        @(Get-CCFChainAnchor -EventLogSource 'ArgosCCF Tests' -EventId 1234 -ChainId 'other').Count | Should -Be 0
        Register-CCFChainAnchor
    }

    It 'writes real events (CI only, so your event log stays clean)' -Skip:(-not $env:GITHUB_ACTIONS -or $IsLinux -or $IsMacOS) {
        $source = 'ArgosCCF CI ' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $folder = Join-Path $TestDrive 'eventlog-ci'
        Initialize-CCFLogger -Path $folder -Chain Audit
        Register-CCFChainAnchor -EventLogSource $source
        Write-CCFAuditRecord -Action 'A' -User 'u'
        Register-CCFChainAnchor
        $anchors = @(Get-CCFChainAnchor -EventLogSource $source)
        $anchors.Count | Should -Be 1
        (Test-CCFLogChain -Path (Join-Path $folder 'CCF_Audit.log') -ExpectedLastHash $anchors).Valid | Should -BeTrue
    }
}

Describe 'Write lock' {
    It 'writes even when the lock was created by another account and cannot be opened' -Skip:($IsLinux -or $IsMacOS) {
        $log = Join-Path $TestDrive 'locked\CCF_Audit.log'
        $null = New-Item -ItemType Directory -Path (Split-Path $log) -Force
        $name = InModuleScope ArgosCCF -Parameters @{ Log = $log } { param($Log) Get-CCFFileMutexName -Path $Log }
        # Only SYSTEM can open it, like a lock created with other permissions: the creator keeps its handle.
        $security = New-Object System.Security.AccessControl.MutexSecurity
        $security.AddAccessRule((New-Object System.Security.AccessControl.MutexAccessRule ([System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')), 'FullControl', 'Allow'))
        $created = $false
        $acl = 'System.Threading.MutexAcl' -as [type]
        $held = if ($acl) { $acl::Create($false, $name, [ref]$created, $security) } else { New-Object System.Threading.Mutex $false, $name, ([ref]$created), $security }
        try {
            $created | Should -BeTrue
            InModuleScope ArgosCCF -Parameters @{ Log = $log } { param($Log) $null = Add-CCFLogText -Path $Log -Text ("line" + [Environment]::NewLine) }
            Get-Content $log | Should -Be 'line'
        }
        finally { $held.Dispose() }
    }

    It 'creates the lock so that every account can open it' -Skip:($IsLinux -or $IsMacOS) {
        $mutex = InModuleScope ArgosCCF { New-CCFFileMutex -Path (Join-Path $TestDrive 'acl.log') }
        try {
            $acl = 'System.Threading.ThreadingAclExtensions' -as [type]
            $rules = if ($acl) { $acl::GetAccessControl($mutex) } else { $mutex.GetAccessControl() }
            @($rules.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value }) | Should -Contain 'S-1-5-11'
        }
        finally { $mutex.Dispose() }
    }
}

Describe 'What a check is worth' {
    It 'says how many hashes from outside the file were checked' {
        $folder = Join-Path $TestDrive 'external'
        Initialize-CCFLogger -Path $folder -Chain Audit
        Write-CCFAuditRecord -Action 'A' -User 'u'
        $log = Join-Path $folder 'CCF_Audit.log'
        (Test-CCFLogChain -Path $log).ExternalHashes | Should -Be 0
        (Test-CCFLogChain -Path $log -ExpectedLastHash (Get-CCFLogChainHead -Path $log)).ExternalHashes | Should -Be 1
    }
}
