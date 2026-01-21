Describe "ArgosCCF: Motor de Plugins (Professional API)" {
    BeforeAll {
        Import-Module "C:\test\ArgosCCF\ArgosCCF.psd1" -Force
    }

    Context "Firma y Seguridad" {
        It "Debe confirmar firma (Confirm-CCFPluginSignature)" {
            $plugins = Get-CCFPlugins
            if ($plugins.Count -gt 0) {
                $res = Confirm-CCFPluginSignature -Path $plugins[0].Path
                $res.Valid | Should -BeOfType [bool]
            }
        }
    }

    Context "Sandboxing" {
        It "Debe forzar el modo de lenguaje restringido" {
            $tmp = Join-Path $env:TEMP "SandboxTest.ps1"
            'param($Arguments) return $ExecutionContext.SessionState.LanguageMode' | Set-Content $tmp
            $p = [PSCustomObject]@{ Name = "SandboxTest"; Path = $tmp }
            $res = Invoke-CCFPlugin -Plugin $p -HardenedMode
            $res | Should -Be "ConstrainedLanguage"
            if (Test-Path $tmp) { Remove-Item $tmp }
        }
    }

    Context "Retrocompatibilidad (Alias)" {
        It "El alias Test-CCFPluginSignature debe apuntar a Confirm-CCFPluginSignature" {
            (Get-Alias Test-CCFPluginSignature).Definition | Should -Be "Confirm-CCFPluginSignature"
        }
    }
}
