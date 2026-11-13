Describe "ArgosCCF: plugins end to end" {
    BeforeAll {
        Import-Module (Join-Path $PSScriptRoot "../../ArgosCCF.psd1") -Force
        $pluginRoot = Get-CCFPath -Target "Plugins"
        $testDir = Join-Path $pluginRoot ("Test_" + [guid]::NewGuid().ToString("N").Substring(0, 8))
        New-Item -ItemType Directory -Path $testDir -Force | Out-Null
    }

    AfterAll {
        Remove-Item $testDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It "reads name and version from ccf_plugin.json" {
        @{ Name = "Manifest-Plugin"; Version = "2.0.0"; Author = "Tests" } | ConvertTo-Json |
            Set-Content (Join-Path $testDir "ccf_plugin.json")
        "return 'manifest ok'" | Set-Content (Join-Path $testDir "Plugin.ps1")

        $plugin = Get-CCFPlugins -Path $testDir | Where-Object Name -EQ "Manifest-Plugin"

        $plugin | Should -Not -BeNullOrEmpty
        $plugin.Version | Should -Be "2.0.0"
        Remove-Item (Join-Path $testDir "ccf_plugin.json")
    }

    It "runs Before-Execute and After-Execute hooks around the plugin" {
        $path = Join-Path $testDir "Lifecycle.ps1"
        @'
param($Arguments)
function Before-Execute { param($Arguments) $global:CCFTestHooks += "before:$($Arguments.Task)" }
function After-Execute { param($Result) $global:CCFTestHooks += "after:$Result" }
return "Success-Lifecycle"
'@ | Set-Content $path
        $global:CCFTestHooks = @()

        $result = Invoke-CCFPlugin -Plugin ([PSCustomObject]@{ Name = "Lifecycle"; Path = $path }) -Arguments @{ Task = "Check" }

        $result | Should -Be "Success-Lifecycle"
        $global:CCFTestHooks | Should -Be @("before:Check", "after:Success-Lifecycle")
        Remove-Variable CCFTestHooks -Scope Global
    }

    It "refuses to run a plugin outside the Plugins folder" {
        $outside = Join-Path ([IO.Path]::GetTempPath()) "Outside_$([guid]::NewGuid().ToString('N')).ps1"
        "return 'should not run'" | Set-Content $outside
        try {
            Invoke-CCFPlugin -Plugin ([PSCustomObject]@{ Name = "Outside"; Path = $outside }) | Should -BeNullOrEmpty
        }
        finally {
            Remove-Item $outside -ErrorAction SilentlyContinue
        }
    }

    It "refuses an unsigned plugin when RequireSignedPlugins is on" {
        $path = Join-Path $testDir "Unsigned.ps1"
        "return 'unsigned ran'" | Set-Content $path
        Mock -ModuleName ArgosCCF Get-CCFConfig { [PSCustomObject]@{ Security = [PSCustomObject]@{ RequireSignedPlugins = $true } } }

        Invoke-CCFPlugin -Plugin ([PSCustomObject]@{ Name = "Unsigned"; Path = $path }) | Should -BeNullOrEmpty
    }

    It "runs an unsigned plugin when RequireSignedPlugins is off" {
        $path = Join-Path $testDir "Unsigned.ps1"
        "return 'unsigned ran'" | Set-Content $path

        Invoke-CCFPlugin -Plugin ([PSCustomObject]@{ Name = "Unsigned"; Path = $path }) | Should -Be "unsigned ran"
    }
}
