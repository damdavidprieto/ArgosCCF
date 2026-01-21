Describe "ArgosCCF: Motor de Logging (Professional API)" {
    BeforeAll {
        Import-Module "C:\test\ArgosCCF\ArgosCCF.psd1" -Force
    }

    Context "Seguridad: Protección y Entropía" {
        It "Debe identificar entropía en tokens complejos (Test-CCFEntropyContent)" {
            Test-CCFEntropyContent -String "A1b2C3d4_E5f6G7h8-I9j0" | Should -Be $true
        }

        It "Debe proteger passwords en strings (Protect-CCFSensitiveData)" {
            Protect-CCFSensitiveData -InputData "password=Secret123!" | Should -Match "\[REDACTED\]"
        }
        
        It "Debe proteger por entropía en diccionarios (Protect-CCFSensitiveData)" {
            $data = @{ Token = "Ak82_mN91-Zq5v_Pz92" }
            $res = Protect-CCFSensitiveData -InputData $data
            $res.Token | Should -Be "[REDACTED]"
        }
    }

    Context "Robustez de Datos" {
        It "Debe manejar y proteger PSCustomObjects" {
            $obj = [PSCustomObject]@{ Key = "Value"; Secret = "A1b2C3d4_E5f6G7h8" }
            $res = Protect-CCFSensitiveData -InputData $obj
            $res.Secret | Should -Be "[REDACTED]"
        }

        It "Debe proteger contra recursión profunda (Depth Limit)" {
            $data = @{ n = @{ n = @{ n = @{ n = @{ n = @{ n = "Limit" } } } } } }
            $res = Protect-CCFSensitiveData -InputData $data
            $res.n.n.n.n.n.n | Should -Be "[DEPTH-LIMIT]"
        }
    }

    Context "Retrocompatibilidad (Alias)" {
        It "El alias Log-Info debe apuntar a Write-CCFLogInfo" {
            (Get-Alias Log-Info).Definition | Should -Be "Write-CCFLogInfo"
        }

        It "El alias Redact-CCFSensitiveData debe apuntar a Protect-CCFSensitiveData" {
            (Get-Alias Redact-CCFSensitiveData).Definition | Should -Be "Protect-CCFSensitiveData"
        }

        It "El alias Test-CCFHighEntropy debe apuntar a Test-CCFEntropyContent" {
            (Get-Alias Test-CCFHighEntropy).Definition | Should -Be "Test-CCFEntropyContent"
        }
        
        It "El alias Log-Attack debe apuntar a Write-CCFSecurityRecord" {
            (Get-Alias Log-Attack).Definition | Should -Be "Write-CCFSecurityRecord"
        }
    }
}
