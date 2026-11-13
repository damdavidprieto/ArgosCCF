Describe "ArgosCCF: logging end to end" {
    BeforeAll {
        Import-Module (Join-Path $PSScriptRoot "../../ArgosCCF.psd1") -Force
        $logDir = Get-CCFPath -Target "Logs"
        $runId = [guid]::NewGuid().ToString("N").Substring(0, 8)
        $sessionLog = "CCF_Test_$runId.log"
        Initialize-CCFLogger -FileName $sessionLog
        $sessionPath = Join-Path $logDir $sessionLog

        function Get-LastLine([string]$Path) { Get-Content -Path $Path -Tail 1 }
    }

    AfterAll {
        Remove-Item (Join-Path $logDir "CCF_Test_*") -ErrorAction SilentlyContinue
    }

    Context "Redaction in the log file" {
        It "redacts key=value secrets" {
            Write-CCFLogInfo "login user=admin password=SuperSecret123! ($runId)"
            $line = Get-LastLine $sessionPath
            $line | Should -Match "\[REDACTED\]"
            $line | Should -Not -Match "SuperSecret123"
        }

        It "redacts high-entropy tokens" {
            Write-CCFLogInfo "key AKIA-872H-J92K-LL92-MM102-PP01 ($runId)"
            $line = Get-LastLine $sessionPath
            $line | Should -Match "REDACTED-ENTROPY"
            $line | Should -Not -Match "AKIA-872H"
        }

        It "keeps the old (message, data) positional form working" {
            { Write-CCFLogWarn "positional ($runId)" @{ port = 8080 } } | Should -Not -Throw
            Get-LastLine $sessionPath | Should -Match "positional \($runId\)"
        }
    }

    Context "Security and audit records" {
        It "routes Log-Attack to CCF_Security.log" {
            Log-Attack -Type "SQLInjection" -Source "10.0.0.5" -Payload "id=1' OR '1'='1" -Metadata @{ run = $runId }
            Get-LastLine (Join-Path $logDir "CCF_Security.log") | Should -Match "SQLInjection from 10\.0\.0\.5"
        }

        It "routes Log-Audit to CCF_Audit.log" {
            Log-Audit -Action "FileDeletion" -User "audit-$runId" -Resource "db.bak"
            Get-LastLine (Join-Path $logDir "CCF_Audit.log") | Should -Match "audit-$runId FileDeletion db\.bak"
        }
    }

    Context "JSON output" {
        It "writes one JSON object per line when -JsonOutput is set" {
            $jsonLog = "CCF_Test_${runId}_json.log"
            Initialize-CCFLogger -FileName $jsonLog -JsonOutput
            try {
                Write-CCFLogSuccess "json line ($runId)" @{ token = "abc" }
                $entry = Get-LastLine (Join-Path $logDir $jsonLog) | ConvertFrom-Json
                $entry.Level | Should -Be "SUCCESS"
                $entry.Data.token | Should -Be "[REDACTED]"
            }
            finally {
                Initialize-CCFLogger -FileName $sessionLog
            }
        }
    }

    Context "Log maintenance" {
        It "zips and deletes logs older than the retention period" {
            $old = Join-Path $logDir "CCF_Test_${runId}_old.log.1"
            "old data" | Out-File $old
            (Get-Item $old).LastWriteTime = (Get-Date).AddDays(-10)
            $before = @(Get-ChildItem $logDir -Filter "CCF_Archive_*.zip").Count

            $removed = Remove-OldCCFLogs -DaysToKeep 5 -CompressBeforeDelete

            $removed | Should -Contain (Split-Path $old -Leaf)
            Test-Path $old | Should -BeFalse
            @(Get-ChildItem $logDir -Filter "CCF_Archive_*.zip").Count | Should -BeGreaterThan $before
            Get-ChildItem $logDir -Filter "CCF_Archive_*.zip" | Sort-Object LastWriteTime | Select-Object -Last 1 | Remove-Item
        }
    }
}
