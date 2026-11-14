Describe "ArgosCCF: health and records" {
    BeforeAll {
        $manifest = Join-Path $PSScriptRoot "../../ArgosCCF.psd1"
        Import-Module $manifest -Force
    }

    Context "Health" {
        It "returns a valid health report (Test-CCFHealth)" {
            $health = Test-CCFHealth
            $health.Status | Should -Match "OK|DEGRADED|CRITICAL"
        }
    }

    Context "Records" {
        It "records security events (Write-CCFSecurityRecord)" {
            { Write-CCFSecurityRecord -Type "Test" -Source "Unit" -Payload "None" } | Should -Not -Throw
        }

        It "records audit events (Write-CCFAuditRecord)" {
            { Write-CCFAuditRecord -Action "Test" -User "Bot" } | Should -Not -Throw
        }
    }

    Context "Aliases for earlier names" {
        It "alias Catch-CCFError points to Write-CCFErrorRecord" {
            (Get-Alias Catch-CCFError).Definition | Should -Be "Write-CCFErrorRecord"
        }

        It "alias Init-CCFLogger points to Initialize-CCFLogger" {
            (Get-Alias Init-CCFLogger).Definition | Should -Be "Initialize-CCFLogger"
        }
    }
}
