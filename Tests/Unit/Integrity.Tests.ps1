# ArgosCCF 2.1: signed chains, checks in one step, who wrote each line, clock warnings, evidence packages and
# the cheaper writes.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../ArgosCCF.psd1') -Force
    Mock -ModuleName ArgosCCF Write-Host { }

    function New-AuditLog([string]$Name, [int]$Count = 3, [hashtable]$Options = @{}) {
        $folder = Join-Path $TestDrive $Name
        Initialize-CCFLogger -Path $folder -Chain Audit @Options
        for ($i = 1; $i -le $Count; $i++) { Write-CCFAuditRecord -Action "Change$i" -User 'tester' -Resource "item$i" }
        return Join-Path $folder 'CCF_Audit.log'
    }

    # What someone who can write the file but has no key can do: rewrite every line with a plain chain.
    function Set-PlainChain([string]$Log) {
        InModuleScope ArgosCCF -Parameters @{ Log = $Log } {
            param($Log)
            $previous = $script:CCFChain.Genesis
            $lines = foreach ($line in [System.IO.File]::ReadAllLines($Log)) {
                $text = (Split-CCFChainLine -Line $line).Text -replace 'Change2', 'Nothing'
                $previous = Get-CCFChainHash -Previous $previous -Line $text
                "$text #chain=$previous"
            }
            [System.IO.File]::WriteAllLines($Log, [string[]]$lines)
        }
    }
}

AfterAll {
    InModuleScope ArgosCCF {
        $script:CCFPaths.LogsPathOverride = $null; $script:CCFLog.CurrentLogFile = $null; $script:CCFChain.Categories = @(); $script:CCFChain.Id = ''
        $script:CCFChain.Key = $null; $script:CCFLog.WriterInfo = $null; $script:CCFLog.NoConsole = $false
        $script:CCFChain.AnchorFailures = 0
    }
}

Describe 'Chain signed with a key' -Skip:($IsLinux -or $IsMacOS) {
    BeforeAll {
        $keyFile = Join-Path $TestDrive 'keys\chain.key'
        $null = New-CCFChainKey -Path $keyFile
    }

    It 'signs every line, and the log is checked only with the key' {
        $log = New-AuditLog 'signed' -Options @{ ChainKeyPath = $keyFile }
        Get-Content $log | Should -Match ' #mac=[0-9a-f]{64}$'
        InModuleScope ArgosCCF { $script:CCFChain.Key = $null }
        $without = Test-CCFLogChain -Path $log
        $without.Valid | Should -BeFalse
        $without.Reason | Should -Match 'chain key'
        $with = Test-CCFLogChain -Path $log -ChainKeyPath $keyFile
        $with.Valid | Should -BeTrue
        $with.KeyedEntries | Should -Be 3
    }

    It 'finds a log rewritten by someone without the key' {
        $log = New-AuditLog 'rewritten' -Options @{ ChainKeyPath = $keyFile }
        Set-PlainChain $log
        # Without the key the forged log looks consistent; with it, it does not.
        InModuleScope ArgosCCF { $script:CCFChain.Key = $null }
        (Test-CCFLogChain -Path $log).Valid | Should -BeTrue
        $r = Test-CCFLogChain -Path $log -ChainKeyPath $keyFile
        $r.Valid | Should -BeFalse
        $r.Reason | Should -Match 'not signed'
    }

    It 'finds an unsigned line after signed ones, and a signed line changed' {
        $log = New-AuditLog 'appended' -Options @{ ChainKeyPath = $keyFile }
        InModuleScope ArgosCCF -Parameters @{ Log = $log } {
            param($Log)
            $text = '[2026-01-01T00:00:00.000Z] [INFO] [Audit] [AUDIT] forged'
            Add-Content -Path $Log -Value "$text #chain=$(Get-CCFChainHash -Previous (Get-CCFLastChainHash -Path $Log) -Line $text)"
        }
        (Test-CCFLogChain -Path $log -ChainKeyPath $keyFile).Reason | Should -Match 'unsigned line follows'
        $log = New-AuditLog 'changed' -Options @{ ChainKeyPath = $keyFile }
        (Get-Content $log -Raw).Replace('Change2', 'Nothing') | Set-Content $log -NoNewline
        (Test-CCFLogChain -Path $log -ChainKeyPath $keyFile).BrokenAt | Should -Match ':2$'
    }

    It 'keeps signing across rotation and retention' {
        $folder = Join-Path $TestDrive 'signed-rotation'
        Initialize-CCFLogger -Path $folder -Chain Audit -ChainKeyPath $keyFile -MaxMB 1 -MaxRolling 2
        $pad = 'x' * 300000
        foreach ($i in 1..14) { Write-CCFAuditRecord -Action "Change$i $pad" -User 'u' }
        $log = Join-Path $folder 'CCF_Audit.log'
        (Test-CCFLogChain -Path $log -IncludeRotated -ChainKeyPath $keyFile).Valid | Should -BeTrue
        (Get-Item "$log.2").LastWriteTime = (Get-Date).AddDays(-60)
        $null = Remove-CCFOldLog -DaysToKeep 30
        $r = Test-CCFLogChain -Path $log -IncludeRotated -ChainKeyPath $keyFile
        $r.Valid | Should -BeTrue
        $r.KeyedEntries | Should -Be $r.Entries
    }

    It 'does not accept an unsigned line that claims earlier lines were archived' {
        $log = New-AuditLog 'fake-archive' -Options @{ ChainKeyPath = $keyFile }
        $lines = @(Get-Content $log)
        $hash = [regex]::Match($lines[0], '#mac=([0-9a-f]{64})').Groups[1].Value
        $fake = "[2026-11-26T10:00:00.000Z] [INFO] [Chain] [CHAIN] Archived CCF_Audit.log.1: 1 lines up to 2099-01-01T00:00:00.000Z, last hash $hash"
        Set-Content -Path $log -Value (@($fake) + $lines[1..2])
        (Test-CCFLogChain -Path $log -IncludeRotated -ChainKeyPath $keyFile).Valid | Should -BeFalse
    }

    It 'keeps the copies of a signed log when the session has no key, and checks the signature in Test-CCFHealth' {
        $folder = Join-Path $TestDrive 'signed-retention'
        Initialize-CCFLogger -Path $folder -Chain Audit -ChainKeyPath $keyFile -MaxMB 1 -MaxRolling 2
        $pad = 'x' * 300000
        foreach ($i in 1..10) { Write-CCFAuditRecord -Action "Change$i $pad" -User 'u' }
        $log = Join-Path $folder 'CCF_Audit.log'
        (Get-Item "$log.2").LastWriteTime = (Get-Date).AddDays(-60)
        InModuleScope ArgosCCF { $script:CCFChain.Key = $null }
        $removed = @(Remove-CCFOldLog -DaysToKeep 30 -WarningVariable warned -WarningAction SilentlyContinue)
        $removed.Count | Should -Be 0
        "$warned" | Should -Match 'signed'
        "$log.2" | Should -Exist

        $log = New-AuditLog 'signed-health' -Options @{ ChainKeyPath = $keyFile }
        (Test-CCFHealth -VerifyChain).Status | Should -Be 'OK'
        Set-PlainChain $log
        (Test-CCFHealth -VerifyChain).Status | Should -Be 'DEGRADED'
    }

    It 'does not replace a key unless told to, and says when the key cannot be read' {
        { New-CCFChainKey -Path $keyFile } | Should -Throw '*already exists*'
        $broken = Join-Path $TestDrive 'keys\broken.key'
        [System.IO.File]::WriteAllBytes($broken, [byte[]](1..40))
        { Initialize-CCFLogger -Path (Join-Path $TestDrive 'broken') -Chain Audit -ChainKeyPath $broken } | Should -Throw '*cannot be read by this account*'
        $null = New-CCFChainKey -Path (Join-Path $TestDrive 'keys\whatif.key') -WhatIf
        Join-Path $TestDrive 'keys\whatif.key' | Should -Not -Exist
    }
}

Describe 'Checks in one step' {
    It 'reads the anchors of the file from the event log' -Skip:($IsLinux -or $IsMacOS) {
        $log = New-AuditLog 'anchors'
        $head = Get-CCFLogChainHead -Path $log
        Mock -ModuleName ArgosCCF Get-CCFChainAnchor { [pscustomobject]@{ File = 'CCF_Audit.log'; Category = 'Audit'; Hash = $head; ChainId = ''; Time = [datetime]::UtcNow } }.GetNewClosure()
        $r = Test-CCFLogChain -Path $log -EventLogSource 'ArgosCCF Tests'
        $r.Valid | Should -BeTrue
        $r.ExternalHashes | Should -Be 1
        Should -Invoke -ModuleName ArgosCCF Get-CCFChainAnchor -Times 1 -ParameterFilter { $Path -eq $log -and $EventLogSource -eq 'ArgosCCF Tests' }
        Mock -ModuleName ArgosCCF Get-CCFChainAnchor { [pscustomobject]@{ File = 'CCF_Audit.log'; Category = 'Audit'; Hash = ('ef' * 32); ChainId = ''; Time = [datetime]::UtcNow } }
        (Test-CCFLogChain -Path $log -EventLogSource 'ArgosCCF Tests').MissingHashes | Should -Be ('ef' * 32)
    }

    It 'checks the chained logs in Test-CCFHealth -VerifyChain' {
        $log = New-AuditLog 'health'
        $check = (Test-CCFHealth -VerifyChain).Checks | Where-Object { $_.Target -eq 'Chain:Audit' }
        $check.Pass | Should -BeTrue
        @((Test-CCFHealth).Checks | Where-Object { $_.Target -like 'Chain:*' }).Count | Should -Be 0
        (Get-Content $log -Raw).Replace('Change2', 'Nothing') | Set-Content $log -NoNewline
        $health = Test-CCFHealth -VerifyChain
        $health.Status | Should -Be 'DEGRADED'
        ($health.Checks | Where-Object { $_.Target -eq 'Chain:Audit' }).Reason | Should -Match 'does not match'
    }
}

Describe 'Who wrote each line' {
    It 'adds the account, elevation and process to text and JSON lines, inside the chain' {
        $log = New-AuditLog 'writer' -Options @{ WriterInfo = $true }
        $line = (Get-Content $log)[0]
        $line | Should -Match " #by=[^ ;]+;(elevated|standard);pid=$PID #chain="
        (Test-CCFLogChain -Path $log).Valid | Should -BeTrue
        (Get-Content $log -Raw).Replace(";pid=$PID", ';pid=1') | Set-Content $log -NoNewline
        (Test-CCFLogChain -Path $log).Valid | Should -BeFalse

        $json = New-AuditLog 'writer-json' -Count 1 -Options @{ WriterInfo = $true; JsonOutput = $true }
        $entry = Get-Content $json | ConvertFrom-Json
        $entry.Writer.ProcessId | Should -Be $PID
        $entry.Writer.User | Should -Not -BeNullOrEmpty
    }

    It 'writes nothing about the writer unless asked' {
        $log = New-AuditLog 'no-writer' -Count 1
        Get-Content $log | Should -Not -Match '#by='
    }
}

Describe 'Clock warnings' {
    It 'reports a line earlier than the one before, without making the log invalid' {
        $log = Join-Path $TestDrive 'clock\CCF_Audit.log'
        $null = New-Item -ItemType Directory -Path (Split-Path $log) -Force
        InModuleScope ArgosCCF -Parameters @{ Log = $log } {
            param($Log)
            foreach ($time in '2026-11-26T10:00:00.000Z', '2026-11-26T10:05:00.000Z', '2026-11-26T09:00:00.000Z', '2026-11-26T10:05:02.000Z') {
                $null = Add-CCFLogText -Path $Log -Text ("[$time] [INFO] [Audit] [AUDIT] entry" + [Environment]::NewLine) -Chain
            }
        }
        $r = Test-CCFLogChain -Path $log
        $r.Valid | Should -BeTrue
        @($r.ClockWarnings).Count | Should -Be 1
        $r.ClockWarnings[0] | Should -Match ':3: 3900 seconds earlier'
        @((Test-CCFLogChain -Path $log -ClockToleranceSeconds 4000).ClockWarnings).Count | Should -Be 0
    }
}

Describe 'Evidence package' {
    It 'packs the log, its copies and the check, with the hash of every file' {
        $log = New-AuditLog 'evidence'
        $zip = Join-Path $TestDrive 'out\evidence.zip'
        $r = Export-CCFEvidence -Path $log -Destination $zip
        $r.Valid | Should -BeTrue
        $r.Sha256 | Should -Be (Get-FileHash -Path $zip -Algorithm SHA256).Hash.ToLowerInvariant()
        $open = Join-Path $TestDrive 'out\open'
        Expand-Archive -Path $zip -DestinationPath $open
        $manifest = Get-Content (Join-Path $open 'evidence.json') -Raw | ConvertFrom-Json
        $manifest.Format | Should -Be 'ArgosCCF evidence v1'
        $manifest.Logs[0].Path | Should -Be $log
        $manifest.Logs[0].Check.Entries | Should -Be 3
        $file = $manifest.Logs[0].Files[0]
        $file.Sha256 | Should -Be (Get-FileHash -Path (Join-Path $open $file.Name) -Algorithm SHA256).Hash.ToLowerInvariant()
        { Export-CCFEvidence -Path $log -Destination $zip } | Should -Throw '*already exists*'
    }

    It 'says when a log does not check out, and includes the anchors' -Skip:($IsLinux -or $IsMacOS) {
        $log = New-AuditLog 'evidence-bad'
        $head = Get-CCFLogChainHead -Path $log
        Mock -ModuleName ArgosCCF Get-CCFChainAnchor { [pscustomobject]@{ File = 'CCF_Audit.log'; Category = 'Audit'; Hash = $head; ChainId = ''; Time = [datetime]::UtcNow } }.GetNewClosure()
        (Get-Content $log -Raw).Replace('Change2', 'Nothing') | Set-Content $log -NoNewline
        $zip = Join-Path $TestDrive 'out\bad.zip'
        $r = Export-CCFEvidence -Path $log -Destination $zip -EventLogSource 'ArgosCCF Tests'
        $r.Valid | Should -BeFalse
        $r.Logs[0].Reason | Should -Match 'does not match'
        $open = Join-Path $TestDrive 'out\bad'
        Expand-Archive -Path $zip -DestinationPath $open
        (Get-Content (Join-Path $open 'evidence.json') -Raw | ConvertFrom-Json).Logs[0].Check.BrokenAt | Should -Be "${log}:2"
        @(Get-Content (Join-Path $open 'anchors.json') -Raw | ConvertFrom-Json).Count | Should -Be 1
    }
}

Describe 'Cheaper writes' {
    It 'keeps the lock of each file open' -Skip:($IsLinux -or $IsMacOS) {
        InModuleScope ArgosCCF -Parameters @{ Log = (Join-Path $TestDrive 'lock.log') } {
            param($Log)
            [object]::ReferenceEquals((Get-CCFFileMutex -Path $Log), (Get-CCFFileMutex -Path $Log)) | Should -BeTrue
        }
    }

    It 'finds the last hash also after a line longer than the first piece read' {
        $log = New-AuditLog 'long-line' -Count 1
        Write-CCFAuditRecord -Action ('word ' * 3000) -User 'u'
        Write-CCFAuditRecord -Action 'After' -User 'u'
        Add-Content -Path $log -Value ''
        $r = Test-CCFLogChain -Path $log
        $r.Valid | Should -BeTrue
        $r.Entries | Should -Be 3
        Get-CCFLogChainHead -Path $log | Should -Be $r.LastHash
    }

    It 'writes nothing to the console with -NoConsole' {
        Initialize-CCFLogger -Path (Join-Path $TestDrive 'quiet') -NoConsole
        Write-CCFLogInfo 'quiet'
        Should -Invoke -ModuleName ArgosCCF Write-Host -Times 0 -Exactly
        Initialize-CCFLogger -Path (Join-Path $TestDrive 'quiet')
        Write-CCFLogInfo 'loud'
        Should -Invoke -ModuleName ArgosCCF Write-Host -Times 1 -Exactly
    }
}
