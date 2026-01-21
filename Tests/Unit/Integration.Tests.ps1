Describe "ArgosCCF: Integración y Ecosistema (Professional API)" {
    BeforeAll {
        Import-Module "C:\test\ArgosCCF\ArgosCCF.psd1" -Force
    }

    Context "Salud del Sistema" {
        It "Debe retornar un reporte de salud válido (Test-CCFHealth)" {
            $health = Test-CCFHealth
            $health.Status | Should -Match "OK|DEGRADED|CRITICAL"
        }
    }

    Context "Capa de Registro (Records)" {
        It "Debe registrar eventos de seguridad (Write-CCFSecurityRecord)" {
            { Write-CCFSecurityRecord -Type "Test" -Source "Unit" -Payload "None" } | Should -Not -Throw
        }

        It "Debe registrar eventos de auditoría (Write-CCFAuditRecord)" {
            { Write-CCFAuditRecord -Action "Test" -User "Bot" } | Should -Not -Throw
        }
    }

    Context "Retrocompatibilidad (Alias)" {
        It "El alias Catch-CCFError debe apuntar a Write-CCFErrorRecord" {
            (Get-Alias Catch-CCFError).Definition | Should -Be "Write-CCFErrorRecord"
        }
        
        It "El alias Init-CCFLogger debe apuntar a Initialize-CCFLogger" {
            (Get-Alias Init-CCFLogger).Definition | Should -Be "Initialize-CCFLogger"
        }
    }
}
