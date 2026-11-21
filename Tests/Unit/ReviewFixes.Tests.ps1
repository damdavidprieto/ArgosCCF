BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../ArgosCCF.psd1') -Force
}

Describe 'RequireSignedPlugins cannot be switched off by a later layer' {
    BeforeEach {
        $script:saved = $env:CCF_DATA_PATH
        $env:CCF_DATA_PATH = Join-Path $TestDrive ('data_' + [guid]::NewGuid().ToString('N'))
        Initialize-CCFEnvironment -WarningAction SilentlyContinue
        Remove-CCFConfigCache
    }
    AfterEach {
        $env:CCF_DATA_PATH = $script:saved
        Initialize-CCFEnvironment -WarningAction SilentlyContinue
        Remove-CCFConfigCache
    }

    It 'is required when the user layer enables it' {
        Set-CCFUserConfig -ConfigName 'ccf_core' -ConfigObject ([pscustomobject]@{ Security = @{ RequireSignedPlugins = $true } })
        InModuleScope ArgosCCF { Test-CCFSignedPluginsRequired } | Should -BeTrue
    }

    It 'stays required when an earlier layer enables it and the user layer disables it' {
        Set-CCFUserConfig -ConfigName 'ccf_core' -ConfigObject ([pscustomobject]@{ Security = @{ RequireSignedPlugins = $false } })
        Mock -ModuleName ArgosCCF Read-CCFJsonFile {
            if ($Path -like '*Factory*') { [pscustomobject]@{ Security = [pscustomobject]@{ RequireSignedPlugins = $true } } }
            else { [pscustomobject]@{ Security = [pscustomobject]@{ RequireSignedPlugins = $false } } }
        }
        Mock -ModuleName ArgosCCF Get-CCFConfig { [pscustomobject]@{ Security = [pscustomobject]@{ RequireSignedPlugins = $false } } }
        InModuleScope ArgosCCF { Test-CCFSignedPluginsRequired } | Should -BeTrue
    }

    It 'is not required when no layer enables it' {
        InModuleScope ArgosCCF { Test-CCFSignedPluginsRequired } | Should -BeFalse
    }

    It 'is required when a layer cannot be read' {
        Set-CCFUserConfig -ConfigName 'ccf_core' -ConfigObject ([pscustomobject]@{ Security = @{ RequireSignedPlugins = $false } })
        Set-Content -Path (Join-Path (Get-CCFPath -Target 'UserConfigs') 'ccf_core.json') -Value '{ not json'
        Mock -ModuleName ArgosCCF Get-CCFConfig { [pscustomobject]@{} }
        InModuleScope ArgosCCF { Test-CCFSignedPluginsRequired } -WarningAction SilentlyContinue | Should -BeTrue
    }
}

Describe 'Plugin hooks with parameters after the function name' {
    BeforeAll {
        $pluginRoot = Get-CCFPath -Target 'Plugins'
        $testDir = Join-Path $pluginRoot ('Test_' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Path $testDir -Force | Out-Null
    }
    AfterAll { Remove-Item $testDir -Recurse -Force -ErrorAction SilentlyContinue }

    It 'passes -Arguments and -Result to hooks declared as function Name($param)' {
        $path = Join-Path $testDir 'InlineParams.ps1'
        @'
param($Arguments)
function Before-Execute($Arguments) { $global:CCFInlineHooks += "before:$($Arguments.Task)" }
function After-Execute($Result) { $global:CCFInlineHooks += "after:$Result" }
"ran:$($Arguments.Task)"
'@ | Set-Content $path
        $global:CCFInlineHooks = @()
        try {
            Invoke-CCFPlugin -Plugin ([pscustomobject]@{ Name = 'InlineParams'; Path = $path }) -Arguments @{ Task = 'x' } | Should -Be 'ran:x'
            $global:CCFInlineHooks | Should -Be @('before:x', 'after:ran:x')
        }
        finally { Remove-Variable -Name CCFInlineHooks -Scope Global -ErrorAction SilentlyContinue }
    }
}

Describe 'Remove-CCFOldLog -CompressBeforeDelete' {
    BeforeEach {
        $logs = Join-Path $TestDrive ('logs_' + [guid]::NewGuid().ToString('N'))
        Initialize-CCFLogger -Path $logs -FileName 'Current.log'
        $old = Join-Path $logs 'Old.log'
        Set-Content -Path $old -Value 'old entry'
        (Get-Item $old).LastWriteTime = (Get-Date).AddDays(-60)
    }

    It 'deletes nothing when compressing fails' {
        # With -ErrorAction Stop a failing Compress-Archive throws, whatever the kind of error.
        Mock -ModuleName ArgosCCF Compress-Archive { throw 'disk full' }
        $removed = Remove-CCFOldLog -DaysToKeep 30 -CompressBeforeDelete -WarningAction SilentlyContinue
        $removed | Should -BeNullOrEmpty
        $old | Should -Exist
    }

    It 'compresses and then deletes when compressing works' {
        $removed = Remove-CCFOldLog -DaysToKeep 30 -CompressBeforeDelete
        $removed | Should -Be 'Old.log'
        $old | Should -Not -Exist
        @(Get-ChildItem $logs -Filter 'CCF_Archive_*.zip').Count | Should -Be 1
    }
}

Describe 'Invoke-CCFParallel results' {
    It 'counts errors written with Write-Error as failures' {
        $res = Invoke-CCFParallel -InputObjects @(1) -ScriptBlock { param($n) Write-Error "bad $n" }
        $res[0].Status | Should -Be 'Failed'
        $res[0].Error | Should -Match 'bad 1'
    }

    It 'reports retries made, not attempts' {
        $ok = Invoke-CCFParallel -InputObjects @(1) -ScriptBlock { param($n) $n }
        $ok[0].Retries | Should -Be 0
        $failed = Invoke-CCFParallel -InputObjects @(1) -RetryCount 2 -RetryDelayMs 0 -ScriptBlock { throw 'always' }
        $failed[0].Status | Should -Be 'Failed'
        $failed[0].Retries | Should -Be 2
    }
}

Describe 'Audit and Security entries that cannot be written' {
    It 'warn on the console instead of failing silently' {
        Initialize-CCFLogger -Path (Join-Path $TestDrive ('audit_' + [guid]::NewGuid().ToString('N')))
        Mock -ModuleName ArgosCCF Add-CCFLogText { throw 'access denied' }
        Write-CCFAuditRecord -Action 'Delete' -User 'bob' -WarningVariable warnings -WarningAction SilentlyContinue
        ($warnings -join ' ') | Should -Match 'Audit'
    }

    It 'stay quiet for ordinary entries' {
        Initialize-CCFLogger -Path (Join-Path $TestDrive ('info_' + [guid]::NewGuid().ToString('N')))
        Mock -ModuleName ArgosCCF Add-CCFLogText { throw 'access denied' }
        Write-CCFLogInfo 'hello' -WarningVariable warnings -WarningAction SilentlyContinue
        $warnings | Should -BeNullOrEmpty
    }
}
