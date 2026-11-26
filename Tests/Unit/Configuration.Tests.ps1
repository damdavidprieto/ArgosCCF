Describe "ArgosCCF: configuration" {
    BeforeAll {
        $manifest = Join-Path $PSScriptRoot "../../ArgosCCF.psd1"
        Import-Module $manifest -Force
    }

    Context "Path traversal (CWE-22)" {
        It "blocks path traversal in ConfigName" {
            Get-CCFConfig -ConfigName "..\..\Secrets" | Should -BeNullOrEmpty
        }
    }

    Context "Deep merge" {
        It "merges nested objects without losing base values" {
            $base = [PSCustomObject]@{ Settings = [PSCustomObject]@{ Port = 80; Path = "/" } }
            $over = [PSCustomObject]@{ Settings = [PSCustomObject]@{ Port = 443 } }
            $res = Merge-CCFConfig -Base $base -Override $over
            $res.Settings.Port | Should -Be 443
            $res.Settings.Path | Should -Be "/"
        }
    }
}
