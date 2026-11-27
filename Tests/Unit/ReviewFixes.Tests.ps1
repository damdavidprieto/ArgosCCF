BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../ArgosCCF.psd1') -Force
}

Describe 'Remove-CCFOldLog -CompressBeforeDelete' {
    BeforeEach {
        $logs = Join-Path $TestDrive ('logs_' + [guid]::NewGuid().ToString('N'))
        Initialize-CCFLogger -Path $logs -FileName 'Current.log'
        $old = Join-Path $logs 'Old.log'
        Set-Content -Path $old -Value 'old entry'
        (Get-Item $old).LastWriteTime = (Get-Date).AddDays(-60)
    }

    It 'deletes nothing when compressing fails' {
        # With -ErrorAction Stop a failing Compress-Archive throws, whatever the kind of error.
        Mock -ModuleName ArgosCCF Compress-Archive { throw 'disk full' }
        $removed = Remove-CCFOldLog -DaysToKeep 30 -CompressBeforeDelete -WarningAction SilentlyContinue
        $removed | Should -BeNullOrEmpty
        $old | Should -Exist
    }

    It 'compresses and then deletes when compressing works' {
        $removed = Remove-CCFOldLog -DaysToKeep 30 -CompressBeforeDelete
        $removed | Should -Be 'Old.log'
        $old | Should -Not -Exist
        @(Get-ChildItem $logs -Filter 'CCF_Archive_*.zip').Count | Should -Be 1
    }
}

Describe 'Audit and Security entries that cannot be written' {
    It 'warn on the console instead of failing silently' {
        Initialize-CCFLogger -Path (Join-Path $TestDrive ('audit_' + [guid]::NewGuid().ToString('N')))
        Mock -ModuleName ArgosCCF Add-CCFLogText { throw 'access denied' }
        Write-CCFAuditRecord -Action 'Delete' -User 'bob' -WarningVariable warnings -WarningAction SilentlyContinue
        ($warnings -join ' ') | Should -Match 'Audit'
    }

    It 'stay quiet for ordinary entries' {
        Initialize-CCFLogger -Path (Join-Path $TestDrive ('info_' + [guid]::NewGuid().ToString('N')))
        Mock -ModuleName ArgosCCF Add-CCFLogText { throw 'access denied' }
        Write-CCFLogInfo 'hello' -WarningVariable warnings -WarningAction SilentlyContinue
        $warnings | Should -BeNullOrEmpty
    }
}
