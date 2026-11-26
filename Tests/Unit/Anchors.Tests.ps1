# ArgosCCF 2.2: anchors of your own, anchors per category, chains of folders, decoded commands and keys for several
# accounts. Anchors go to memory (Set-CCFAnchorStore): the tests never write to the event log.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../ArgosCCF.psd1') -Force
    Mock -ModuleName ArgosCCF Write-Host { }
    Set-CCFAnchorStore -Store Memory

    function New-ReportFolder([string]$Name) {
        $folder = Join-Path $TestDrive "reports\$Name"
        $null = New-Item -ItemType Directory -Path (Join-Path $folder 'sub') -Force
        Set-Content -Path (Join-Path $folder 'report.txt') -Value "report $Name"
        Set-Content -Path (Join-Path $folder 'sub\events.json') -Value '{"events": 3}'
        return $folder
    }
}

AfterAll {
    Register-CCFChainAnchor
    Set-CCFAnchorStore -Store EventLog
    Set-CCFRedactionOption -EncodedCommand Fingerprint
    InModuleScope ArgosCCF {
        $script:LogsPathOverride = $null; $script:CurrentLogFile = $null; $script:CCFChainCategories = @(); $script:CCFChainId = ''
        $script:CCFChainKey = $null; $script:CCFChainKeyPath = $null; $script:CCFChainAnchorFailures = 0
    }
}

Describe 'Anchors of your own' {
    BeforeEach { Set-CCFAnchorStore -Store Memory -Clear }

    It 'writes a kind and a text, and reads them back by kind, event ID and time' {
        Write-CCFAnchor -Source 'App Tests' -EventId 1001 -Kind 'report' -Text "20261126-101500 $('ab' * 32)" | Should -BeTrue
        Write-CCFAnchor -Source 'App Tests' -EventId 1000 -Kind 'heartbeat' | Should -BeTrue
        Write-CCFAnchor -Source 'Other' -EventId 1001 -Kind 'report' -Text 'other program' | Should -BeTrue
        $reports = @(Get-CCFAnchor -Source 'App Tests' -Kind 'report')
        $reports.Count | Should -Be 1
        $reports[0].Text | Should -Be "20261126-101500 $('ab' * 32)"
        $reports[0].EventId | Should -Be 1001
        $reports[0].Time | Should -BeOfType [datetime]
        (Get-CCFAnchor -Source 'App Tests' -EventId 1000).Kind | Should -Be 'heartbeat'
        (Get-CCFAnchor -Source 'App Tests' -EventId 1000).Text | Should -Be ''
        @(Get-CCFAnchor -Source 'App Tests' -Since (Get-Date).AddMinutes(5)).Count | Should -Be 0
    }

    It 'keeps every anchor on one line and refuses kinds that are not one word' {
        Write-CCFAnchor -Source 'App Tests' -EventId 1001 -Kind 'report' -Text "one`r`ntwo" | Should -BeTrue
        (Get-CCFAnchor -Source 'App Tests').Text | Should -Be 'one\r\ntwo'
        { Write-CCFAnchor -Source 'App Tests' -EventId 1001 -Kind 'two words' -Text 'x' } | Should -Throw
    }

    It 'reads anchors written earlier by another program in the same format' -Skip:($IsLinux -or $IsMacOS) {
        Set-CCFAnchorStore -Store EventLog
        try {
            # As a program wrote them before 2.2.0: "<kind> <text>", one event ID per kind.
            $events = @(
                [pscustomobject]@{ Properties = @([pscustomobject]@{ Value = "auditoria $('ef' * 32)" }); TimeCreated = (Get-Date).AddMinutes(-2); Id = 1005 }
                [pscustomobject]@{ Properties = @([pscustomobject]@{ Value = 'latido' }); TimeCreated = (Get-Date).AddMinutes(-1); Id = 1000 }
            )
            Mock -ModuleName ArgosCCF Get-WinEvent { $events }.GetNewClosure()
            $anchors = @(Get-CCFAnchor -Source 'CassielV2' -EventId 1000, 1005 -Since (Get-Date).AddDays(-1))
            $anchors.Kind -join ',' | Should -Be 'auditoria,latido'
            $anchors[0].Text | Should -Be ('ef' * 32)
            Should -Invoke -ModuleName ArgosCCF Get-WinEvent -Times 1 -ParameterFilter { $FilterXPath -match "Provider\[@Name='CassielV2'\]" -and $FilterXPath -match 'EventID=1000 or EventID=1005' -and $FilterXPath -match '@SystemTime>=' }
        }
        finally { Set-CCFAnchorStore -Store Memory }
    }
}

Describe 'Anchors per category' {
    BeforeEach {
        Set-CCFAnchorStore -Store Memory -Clear
        Register-CCFChainAnchor
        $folder = Join-Path $TestDrive ('categories-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
        Initialize-CCFLogger -Path $folder -Chain Audit, Monitor
        $monitor = Join-Path $folder 'CCF_Monitor.log'
    }

    It 'anchors one log with its own interval, and the others with theirs' {
        Register-CCFChainAnchor -EventLogSource 'App Tests' -EventId 1100
        Register-CCFChainAnchor -EventLogSource 'App Tests' -EventId 1106 -Category 'Monitor' -MinimumSeconds 3600
        Write-CCFAuditRecord -Action 'A' -User 'u'
        Write-CCFAuditRecord -Action 'B' -User 'u'
        foreach ($i in 1..3) { Write-CCFLog -Message "check $i" -Category 'Monitor' }
        @(Get-CCFChainAnchor -EventLogSource 'App Tests' -EventId 1100).Count | Should -Be 2
        @(Get-CCFChainAnchor -EventLogSource 'App Tests' -EventId 1106).Count | Should -Be 1

        # At the end of the task: the last head, whatever the interval.
        $saved = @(Save-CCFChainAnchor -Category 'Monitor')
        $saved[0].Hash | Should -Be (Get-CCFLogChainHead -Path $monitor)
        $r = Test-CCFLogChain -Path $monitor -EventLogSource 'App Tests' -EventId 1106
        $r.Valid | Should -BeTrue
        $r.ExternalHashes | Should -Be 2

        $lines = @(Get-Content $monitor)
        Set-Content -Path $monitor -Value $lines[0..($lines.Count - 2)]
        (Test-CCFLogChain -Path $monitor -EventLogSource 'App Tests' -EventId 1106).Valid | Should -BeFalse
    }

    It 'goes back to the registration for every category when the one of a category is removed' {
        Register-CCFChainAnchor -EventLogSource 'App Tests' -EventId 1100
        Register-CCFChainAnchor -EventLogSource 'App Tests' -EventId 1106 -Category 'Monitor'
        Register-CCFChainAnchor -Category 'Monitor'
        Write-CCFLog -Message 'check' -Category 'Monitor'
        @(Get-CCFChainAnchor -EventLogSource 'App Tests' -EventId 1106).Count | Should -Be 0
        @(Get-CCFChainAnchor -EventLogSource 'App Tests' -EventId 1100 -Category 'Monitor').Count | Should -Be 1
        Register-CCFChainAnchor
        Write-CCFLog -Message 'check' -Category 'Monitor'
        @(Get-CCFChainAnchor -EventLogSource 'App Tests').Count | Should -Be 1
        (Save-CCFChainAnchor) | Should -BeNullOrEmpty
    }

    It 'does not mix the anchors of a log with the same name in another folder' {
        Register-CCFChainAnchor -EventLogSource 'App Tests'
        Write-CCFAuditRecord -Action 'A' -User 'u'
        $mine = Join-Path (Split-Path $monitor) 'CCF_Audit.log'
        # Another copy of the program, with its own folder and the same source.
        Initialize-CCFLogger -Path (Join-Path $TestDrive ('other-' + [guid]::NewGuid().ToString('N').Substring(0, 6))) -Chain Audit
        Write-CCFAuditRecord -Action 'Other' -User 'u'
        Write-CCFAuditRecord -Action 'Other' -User 'u'
        $r = Test-CCFLogChain -Path $mine -EventLogSource 'App Tests'
        $r.Valid | Should -BeTrue
        $r.ExternalHashes | Should -Be 1
        # Anchors written before 2.2.0 carry no folder: they are matched by name.
        InModuleScope ArgosCCF -Parameters @{ Head = (Get-CCFLogChainHead -Path $mine) } {
            param($Head)
            $null = Write-CCFAnchorEvent -Source 'App Tests' -EventId 1100 -Message "ArgosCCF anchor v1 Category=Audit ChainId=- Hash=$Head File=CCF_Audit.log"
        }
        (Test-CCFLogChain -Path $mine -EventLogSource 'App Tests').ExternalHashes | Should -Be 2
    }
}

Describe 'Chains of folders' {
    BeforeEach {
        Set-CCFAnchorStore -Store Memory -Clear
        Register-CCFChainAnchor
        $logs = Join-Path $TestDrive ('folders-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
        Initialize-CCFLogger -Path $logs
        $one = New-ReportFolder ('one-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
        $two = New-ReportFolder ('two-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
    }

    It 'hashes every file with its relative path' {
        $before = Get-CCFFolderHash -Path $one
        $before.Files | Should -Be 2
        (Get-CCFFolderHash -Path $one).Hash | Should -Be $before.Hash
        Rename-Item (Join-Path $one 'report.txt') 'renamed.txt'
        (Get-CCFFolderHash -Path $one).Hash | Should -Not -Be $before.Hash
    }

    It 'finds a folder changed after it was recorded, and tolerates folders deleted by age' {
        Register-CCFChainAnchor -EventLogSource 'App Tests' -Category 'Folders'
        $added = Add-CCFFolderHash -Folder $one
        $null = Add-CCFFolderHash -Folder $two
        $added.Files | Should -Be 2
        $log = $added.Log
        $log | Should -Be (Join-Path $logs 'CCF_Folders.log')
        $r = Test-CCFFolderChain -EventLogSource 'App Tests'
        $r.Valid | Should -BeTrue
        $r.Folders | Should -Be 2
        $r.Chain.ExternalHashes | Should -Be 2

        Add-Content -Path (Join-Path $one 'report.txt') -Value 'changed'
        $r = Test-CCFFolderChain
        $r.Valid | Should -BeFalse
        $r.Changed.Path | Should -Be $one
        # Recording it again accepts the new content.
        $null = Add-CCFFolderHash -Folder $one
        (Test-CCFFolderChain).Valid | Should -BeTrue

        Remove-Item $two -Recurse -Force
        $r = Test-CCFFolderChain
        $r.Valid | Should -BeTrue
        $r.Missing.Path | Should -Be $two
        $r = Test-CCFFolderChain -KeepDays 180
        $r.Valid | Should -BeFalse
        $r.DeletedEarly.Path | Should -Be $two
    }

    It 'ignores folder lines that are not chained, and finds moved folders with -Root' {
        $null = Add-CCFFolderHash -Folder $one
        Add-Content -Path (Join-Path $logs 'CCF_Folders.log') -Value "[2026-11-26T10:00:00.000Z] [INFO] [Folders] [FOLDER] $('0' * 64) files=1 $one"
        $r = Test-CCFFolderChain
        $r.Valid | Should -BeFalse
        $r.Chain.Reason | Should -Match 'without a chain hash'

        $log = Join-Path $logs 'moved\CCF_Folders.log'
        $null = Add-CCFFolderHash -Folder $one -LogPath $log
        $moved = Join-Path $TestDrive ('moved-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
        $null = New-Item -ItemType Directory -Path $moved
        Move-Item $one $moved
        (Test-CCFFolderChain -LogPath $log).Missing.Count | Should -Be 1
        $r = Test-CCFFolderChain -LogPath $log -Root $moved
        $r.Valid | Should -BeTrue
        $r.Missing.Count | Should -Be 0
    }

    It 'packs folders in the evidence and compares them with the hash recorded' {
        $null = Add-CCFFolderHash -Folder $one
        $folderLog = Join-Path $logs 'CCF_Folders.log'
        $zip = Join-Path $TestDrive ('folders-' + [guid]::NewGuid().ToString('N').Substring(0, 6) + '.zip')
        $r = Export-CCFEvidence -Path $folderLog -Folder $one -FolderLog $folderLog -Destination $zip
        $r.Valid | Should -BeTrue
        $r.Folders[0].Matches | Should -BeTrue
        $open = Join-Path $TestDrive ('open-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
        Expand-Archive -Path $zip -DestinationPath $open
        $manifest = Get-Content (Join-Path $open 'evidence.json') -Raw | ConvertFrom-Json
        (Get-CCFFolderHash -Path (Join-Path $open $manifest.Folders[0].Copy)).Hash | Should -Be $manifest.Folders[0].Hash

        Add-Content -Path (Join-Path $one 'report.txt') -Value 'changed'
        $r = Export-CCFEvidence -Folder $one -FolderLog $folderLog -Destination $zip -Force
        $r.Valid | Should -BeFalse
        $r.Folders[0].Matches | Should -BeFalse
        { Export-CCFEvidence -Destination $zip -Force } | Should -Throw '*-Path*-Folder*'
    }
}

Describe 'Options that are not passwords' {
    It 'keeps <Text>' -TestCases @(
        @{ Text = 'net user admin /passwordreq:yes' }
        @{ Text = 'net user admin /passwordchg:no' }
        @{ Text = 'net user admin /active:yes /passwordreq:no /passwordchg:yes' }
    ) {
        Protect-CCFSensitiveData $Text | Should -BeExactly $Text
    }

    It 'still redacts the password next to them' {
        Protect-CCFSensitiveData 'net user admin Zanahoria9 /passwordreq:yes /add' | Should -BeExactly 'net user admin [REDACTED] /passwordreq:yes /add'
        Protect-CCFSensitiveData 'net user admin /passwordreq:yes Zanahoria9' | Should -BeExactly 'net user admin /passwordreq:yes [REDACTED]'
        Protect-CCFSensitiveData 'password: Zanahoria9' | Should -Match 'REDACTED'
    }
}

Describe 'Decoded commands' {
    BeforeAll {
        function ConvertTo-Encoded([string]$Text) { [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Text)) }
    }
    AfterEach { Set-CCFRedactionOption -EncodedCommand Fingerprint }

    It 'keeps a fingerprint by default' {
        Protect-CCFSensitiveData "pwsh -EncodedCommand $(ConvertTo-Encoded 'Write-Output hola')" | Should -Match '^pwsh -EncodedCommand \[ENCODED [0-9a-f]{8} \d+ chars\]$'
    }

    It 'decodes the command and redacts the secrets in it with -EncodedCommand Decode' {
        Set-CCFRedactionOption -EncodedCommand Decode
        $encoded = ConvertTo-Encoded 'net user admin Zanahoria9 /add; Write-Output password=Zanahoria9'
        $out = Protect-CCFSensitiveData "powershell.exe -NoProfile -EncodedCommand $encoded"
        $out | Should -Match '\[DECODED [0-9a-f]{8} \d+ chars: net user admin \[REDACTED\] /add; Write-Output password=\[REDACTED\]\]$'
        $out | Should -Not -Match 'Zanahoria9'
        $out | Should -Not -Match ([regex]::Escape($encoded))
        # The same fingerprint as without decoding, so both modes can be matched.
        Set-CCFRedactionOption -EncodedCommand Fingerprint
        $plain = Protect-CCFSensitiveData "powershell.exe -NoProfile -EncodedCommand $encoded"
        ($plain -replace '^.*\[ENCODED ([0-9a-f]{8}) .*$', '$1') | Should -Be ($out -replace '^.*\[DECODED ([0-9a-f]{8}) .*$', '$1')
    }

    It 'decodes one level only, and keeps the fingerprint of what is not text' {
        Set-CCFRedactionOption -EncodedCommand Decode
        $inner = ConvertTo-Encoded 'Write-Output inner'
        $out = Protect-CCFSensitiveData "pwsh -EncodedCommand $(ConvertTo-Encoded "pwsh -EncodedCommand $inner")"
        $out | Should -Match ': pwsh -EncodedCommand \[ENCODED [0-9a-f]{8} \d+ chars\]\]$'
        Protect-CCFSensitiveData 'pwsh -EncodedCommand AAECAwQFBgcICQoLDA0ODxAR' | Should -Match '\[ENCODED [0-9a-f]{8} \d+ chars\]$'
    }
}

Describe 'A key for several accounts' -Skip:($IsLinux -or $IsMacOS) {
    It 'works for the accounts given, and only they can read the file' {
        $key = Join-Path $TestDrive 'keys\shared.key'
        $null = New-CCFChainKey -Path $key -Reader 'S-1-5-19'
        [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($key), 0, 13) | Should -Be 'ArgosCCF-LM1:'
        $acl = Get-Acl -LiteralPath $key
        $acl.AreAccessRulesProtected | Should -BeTrue
        $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
        ($rules | Where-Object { $_.IdentityReference.Value -eq 'S-1-5-19' }).FileSystemRights.ToString() | Should -Match 'Read'
        @($rules | Where-Object { $_.IdentityReference.Value -in 'S-1-1-0', 'S-1-5-11', 'S-1-5-32-545' }).Count | Should -Be 0

        $folder = Join-Path $TestDrive 'shared-key'
        Initialize-CCFLogger -Path $folder -Chain Audit -ChainKeyPath $key
        Write-CCFAuditRecord -Action 'A' -User 'u'
        $r = Test-CCFLogChain -Path (Join-Path $folder 'CCF_Audit.log') -ChainKeyPath $key
        $r.Valid | Should -BeTrue
        $r.KeyedEntries | Should -Be 1
    }

    It 'checks every account before it writes anything' {
        $key = Join-Path $TestDrive 'keys\nobody.key'
        { New-CCFChainKey -Path $key -Reader 'NoSuchAccount-ArgosCCF-Tests' } | Should -Throw '*does not exist*'
        $key | Should -Not -Exist
    }
}
