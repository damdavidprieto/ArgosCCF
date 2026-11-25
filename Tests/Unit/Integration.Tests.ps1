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

Describe 'A copy without the deprecated components' {
    It 'loads, logs and redacts, and exports only what it has' {
        $copy = Join-Path $TestDrive 'lean\ArgosCCF'
        $root = Join-Path $PSScriptRoot '../..'
        New-Item -ItemType Directory -Path (Join-Path $copy 'Core') -Force | Out-Null
        Copy-Item (Join-Path $root 'ArgosCCF.psd1'), (Join-Path $root 'ArgosCCF.psm1') $copy
        Copy-Item (Join-Path $root 'Core/Redaction.ps1'), (Join-Path $root 'Core/Logging.ps1') (Join-Path $copy 'Core')
        $script = {
            param($Copy, $Data)
            $env:CCF_DATA_PATH = $Data
            $m = Import-Module (Join-Path $Copy 'ArgosCCF.psd1') -PassThru -WarningAction SilentlyContinue
            Register-CCFLogProvider -ProviderScript { param($Entry) $null = $Entry }
            Initialize-CCFLogger -Path (Join-Path $Data 'logs') -Chain Audit
            Write-CCFAuditRecord -Action 'A' -User 'u'
            [pscustomobject]@{
                Redacted = Protect-CCFSensitiveData 'net user bob Zanahoria9 /add'
                Config = [bool]$m.ExportedFunctions['Get-CCFConfig']
                Anchor = [bool]$m.ExportedFunctions['Register-CCFChainAnchor']
                Status = (Test-CCFHealth).Status
                Chain = (Test-CCFLogChain -Path (Join-Path $Data 'logs/CCF_Audit.log')).Valid
            }
        }
        $job = Start-Job -ScriptBlock $script -ArgumentList $copy, (Join-Path $TestDrive 'lean-data')
        $r = Receive-Job $job -Wait -AutoRemoveJob
        $r.Redacted | Should -Be 'net user bob [REDACTED] /add'
        $r.Config | Should -BeFalse
        $r.Anchor | Should -BeTrue
        $r.Status | Should -Be 'OK'
        $r.Chain | Should -BeTrue
    }
}
