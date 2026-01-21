Describe "ArgosCCF: Motor de Configuración (Professional API)" {
    BeforeAll {
        Import-Module "C:\test\ArgosCCF\ArgosCCF.psd1" -Force
    }

    Context "Seguridad (Parche CWE-22)" {
        It "Debe bloquear intentos de Path Traversal en ConfigName" {
            Get-CCFConfig -ConfigName "..\..\Secrets" | Should -BeNullOrEmpty
        }
    }

    Context "Lógica de Fusión (Deep Merge)" {
        It "Debe fusionar objetos anidados sin perder datos base" {
            $base = [PSCustomObject]@{ Settings = [PSCustomObject]@{ Port = 80; Path = "/" } }
            $over = [PSCustomObject]@{ Settings = [PSCustomObject]@{ Port = 443 } }
            $res = Merge-CCFConfig -Base $base -Override $over
            $res.Settings.Port | Should -Be 443
            $res.Settings.Path | Should -Be "/"
        }
    }

    Context "Retrocompatibilidad (Alias)" {
        It "El alias Clear-CCFConfigCache debe apuntar a Remove-CCFConfigCache" {
            (Get-Alias Clear-CCFConfigCache).Definition | Should -Be "Remove-CCFConfigCache"
        }
    }
}
