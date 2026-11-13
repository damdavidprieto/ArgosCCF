Describe "ArgosCCF: Motor de Plugins (Professional API)" {
    BeforeAll {
        $manifest = Join-Path $PSScriptRoot "../../ArgosCCF.psd1"
        Import-Module $manifest -Force
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
            # Plugins only run from the Plugins folder (location check), so the probe goes there.
            $tmp = Join-Path (Get-CCFPath -Target "Plugins") "SandboxTest_$([guid]::NewGuid().ToString('N')).ps1"
            'param($Arguments) return $ExecutionContext.SessionState.LanguageMode' | Set-Content $tmp
            try {
                $p = [PSCustomObject]@{ Name = "SandboxTest"; Path = $tmp }
                $res = Invoke-CCFPlugin -Plugin $p -HardenedMode
                $res | Should -Be "ConstrainedLanguage"
            }
            finally {
                Remove-Item $tmp -ErrorAction SilentlyContinue
            }
        }
    }

    Context "Retrocompatibilidad (Alias)" {
        It "El alias Test-CCFPluginSignature debe apuntar a Confirm-CCFPluginSignature" {
            (Get-Alias Test-CCFPluginSignature).Definition | Should -Be "Confirm-CCFPluginSignature"
        }
    }
}
