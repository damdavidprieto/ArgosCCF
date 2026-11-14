BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../ArgosCCF.psd1') -Force
    $logDir = Get-CCFPath -Target 'Logs'
    $moduleRoot = Get-CCFPath -Target 'Root'
}

AfterAll {
    Get-Module ArgosCCF | Remove-Module -Force
}

Describe 'Log file names' {
    It 'refuses a -Category that would leave the Logs folder' {
        { Write-CCFLog -Message 'x' -Category '..\..\escape' 6>$null } | Should -Throw
        Join-Path $logDir '..\..\escape.log' | Should -Not -Exist
    }

    It 'refuses a -FileName that is a path' {
        { Initialize-CCFLogger -FileName '..\outside.log' } | Should -Throw
        { Initialize-CCFLogger -FileName 'C:\Windows\Temp\x.log' } | Should -Throw
    }

    It 'accepts plain names' {
        { Initialize-CCFLogger -FileName 'Plain_Name-1.log' } | Should -Not -Throw
        { Write-CCFLog -Message 'ok' -Category 'Custom_Cat-1' 6>$null } | Should -Not -Throw
        Join-Path $logDir 'CCF_Custom_Cat-1.log' | Should -Exist
        Remove-Item (Join-Path $logDir 'CCF_Custom_Cat-1.log') -ErrorAction SilentlyContinue
    }
}

Describe 'Log forging' {
    BeforeAll {
        Mock -ModuleName ArgosCCF Write-Host { }
        $category = 'Forge' + [guid]::NewGuid().ToString('N').Substring(0, 6)
        $file = Join-Path $logDir "CCF_$category.log"
    }
    AfterAll {
        Remove-Item $file -ErrorAction SilentlyContinue
    }

    It 'writes a message with line breaks as a single line' {
        # Short messages go through redaction first, which joins words with spaces; longer
        # ones keep their line breaks as the literal text \n. Either way the entry is one line.
        Write-CCFLog -Message "real`n[2026-01-01T00:00:00.000Z] [INFO] [System] forged" -Category $category
        $lines = @(Get-Content $file)
        $lines.Count | Should -Be 1
        $lines[0] | Should -Match 'real.+forged$'
    }

    It 'escapes line breaks in long messages' {
        Remove-Item $file -ErrorAction SilentlyContinue
        Write-CCFLog -Message (('x' * 2100) + "`nforged line") -Category $category
        $lines = @(Get-Content $file)
        $lines.Count | Should -Be 1
        $lines[0] | Should -Match 'x\\nforged line$'
    }

    It 'removes ANSI escape sequences from the console output' {
        Write-CCFLog -Message "status $([char]27)[8mhidden$([char]27)[0m" -Category $category
        Should -Invoke -ModuleName ArgosCCF Write-Host -ParameterFilter { $Object -notmatch "\x1B" -and $Object -match 'status hidden' }
    }
}

Describe 'Configuration names' {
    BeforeAll {
        Mock -ModuleName ArgosCCF Write-Host { }
    }

    It 'Set-CCFUserConfig refuses a name that is a path' {
        Set-CCFUserConfig -ConfigName '..\..\evil' -ConfigObject ([pscustomobject]@{ a = 1 })
        Join-Path (Get-CCFPath -Target 'Configs') '..\evil.json' | Should -Not -Exist
        Join-Path $moduleRoot '..\evil.json' | Should -Not -Exist
    }

    It 'Get-CCFConfig refuses a preset name that is a path' {
        Get-CCFConfig -ConfigName 'ccf_core' -ActivePresets '..\..\secrets' -ForceRefresh | Should -BeNullOrEmpty
    }

    It 'Set-CCFUserConfig supports -WhatIf' {
        $name = 'whatif_' + [guid]::NewGuid().ToString('N').Substring(0, 6)
        Set-CCFUserConfig -ConfigName $name -ConfigObject ([pscustomobject]@{ a = 1 }) -WhatIf
        Join-Path (Get-CCFPath -Target 'Configs') "User/$name.json" | Should -Not -Exist
    }

    It 'keeps cache entries for different preset lists apart' {
        $configs = Get-CCFPath -Target 'Configs'
        $presets = Join-Path $configs 'Presets'
        New-Item -ItemType Directory -Path $presets -Force | Out-Null
        @{ ccf_core = @{ Marker = 'preset' } } | ConvertTo-Json -Depth 3 | Set-Content (Join-Path $presets 'qa_marker.json')
        try {
            (Get-CCFConfig -ConfigName 'ccf_core' -ActivePresets 'qa_marker' -ForceRefresh).Marker | Should -Be 'preset'
            (Get-CCFConfig -ConfigName 'ccf_core' -ForceRefresh).Marker | Should -BeNullOrEmpty
        }
        finally {
            Remove-Item (Join-Path $presets 'qa_marker.json')
            Remove-CCFConfigCache
        }
    }
}

Describe 'Logs folder override' {
    BeforeEach {
        Mock -ModuleName ArgosCCF Write-Host { }
        InModuleScope ArgosCCF { $script:PathCache.Clear() }
    }
    AfterEach {
        InModuleScope ArgosCCF { $script:PathCache.Clear() }
    }

    It 'ignores Logging.DefaultPath when it climbs out of the module with ..' {
        Mock -ModuleName ArgosCCF Get-CCFConfig { [pscustomobject]@{ Logging = [pscustomobject]@{ DefaultPath = '../../outside-logs' } } }
        Get-CCFPath -Target 'Logs' | Should -Not -Match 'outside-logs'
    }

    It 'uses Logging.DefaultPath when it is inside the module folder' {
        Mock -ModuleName ArgosCCF Get-CCFConfig { [pscustomobject]@{ Logging = [pscustomobject]@{ DefaultPath = 'CustomLogs' } } }
        Get-CCFPath -Target 'Logs' | Should -Be ([IO.Path]::GetFullPath((Join-Path $moduleRoot 'CustomLogs')))
    }
}

Describe 'Redaction' {
    It 'redacts secrets in nested string values' {
        $result = Protect-CCFSensitiveData -InputData @{ Note = 'login with password=hunter2!' }
        $result.Note | Should -Match 'password=\[REDACTED\]'
        $result.Note | Should -Not -Match 'hunter2'
    }

    It 'does not treat ordinary words as secrets' {
        Test-CCFEntropyContent -String 'configurationmanagement' | Should -BeFalse
    }

    It 'flags mixed-character tokens as secrets' {
        Test-CCFEntropyContent -String 'ghp_Ab12Cd34Ef56Gh78Ij90' | Should -BeTrue
    }
}
