Describe "ArgosCCF: logging" {
    BeforeAll {
        $manifest = Join-Path $PSScriptRoot "../../ArgosCCF.psd1"
        Import-Module $manifest -Force
    }

    Context "Redaction and entropy" {
        It "detects high-entropy tokens (Test-CCFEntropyContent)" {
            Test-CCFEntropyContent -String "A1b2C3d4_E5f6G7h8-I9j0" | Should -Be $true
        }

        It "redacts passwords in strings (Protect-CCFSensitiveData)" {
            Protect-CCFSensitiveData -InputData "password=Secret123!" | Should -Match "\[REDACTED\]"
        }

        It "redacts high-entropy values in dictionaries (Protect-CCFSensitiveData)" {
            $data = @{ Token = "Ak82_mN91-Zq5v_Pz92" }
            $res = Protect-CCFSensitiveData -InputData $data
            $res.Token | Should -Be "[REDACTED]"
        }
    }

    Context "Data shapes" {
        It "redacts PSCustomObjects" {
            $obj = [PSCustomObject]@{ Key = "Value"; Secret = "A1b2C3d4_E5f6G7h8" }
            $res = Protect-CCFSensitiveData -InputData $obj
            $res.Secret | Should -Be "[REDACTED]"
        }

        It "stops at the depth limit" {
            $data = @{ n = @{ n = @{ n = @{ n = @{ n = @{ n = "Limit" } } } } } }
            $res = Protect-CCFSensitiveData -InputData $data
            $res.n.n.n.n.n.n | Should -Be "[DEPTH-LIMIT]"
        }
    }

    Context "Aliases for earlier names" {
        It "alias Log-Info points to Write-CCFLogInfo" {
            (Get-Alias Log-Info).Definition | Should -Be "Write-CCFLogInfo"
        }

        It "alias Redact-CCFSensitiveData points to Protect-CCFSensitiveData" {
            (Get-Alias Redact-CCFSensitiveData).Definition | Should -Be "Protect-CCFSensitiveData"
        }

        It "alias Test-CCFHighEntropy points to Test-CCFEntropyContent" {
            (Get-Alias Test-CCFHighEntropy).Definition | Should -Be "Test-CCFEntropyContent"
        }

        It "alias Log-Attack points to Write-CCFSecurityRecord" {
            (Get-Alias Log-Attack).Definition | Should -Be "Write-CCFSecurityRecord"
        }
    }
}
