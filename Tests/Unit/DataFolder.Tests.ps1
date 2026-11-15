# Logs and user settings live in the per-user data folder, never in the module folder.

BeforeAll {
    $script:previousDataPath = $env:CCF_DATA_PATH
    $script:dataRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('ArgosCCF-data-' + [guid]::NewGuid().ToString('N'))
    $env:CCF_DATA_PATH = $script:dataRoot
    Import-Module (Join-Path $PSScriptRoot '../../ArgosCCF.psd1') -Force
    Mock -ModuleName ArgosCCF Write-Host { }
    $script:moduleRoot = Get-CCFPath -Target 'Root'
}

AfterAll {
    $env:CCF_DATA_PATH = $script:previousDataPath
    Remove-Item -LiteralPath $script:dataRoot -Recurse -Force -ErrorAction SilentlyContinue
    # Leave the module as other test files expect it: data folder from the environment.
    InModuleScope ArgosCCF { Initialize-CCFEnvironment }
}

Describe 'Data folder' {
    It 'uses $env:CCF_DATA_PATH for the data, logs and user settings folders' {
        Get-CCFPath -Target 'Data' | Should -Be ([System.IO.Path]::GetFullPath($dataRoot))
        Get-CCFPath -Target 'Logs' | Should -Be (Join-Path $dataRoot 'Logs')
        Get-CCFPath -Target 'UserConfigs' | Should -Be (Join-Path (Join-Path $dataRoot 'Configs') 'User')
    }

    It 'defaults to ArgosCCF under the user data folder when $env:CCF_DATA_PATH is not set' {
        $root = InModuleScope ArgosCCF {
            $saved = $env:CCF_DATA_PATH
            try { $env:CCF_DATA_PATH = $null; Get-CCFDataRoot } finally { $env:CCF_DATA_PATH = $saved }
        }
        Split-Path $root -Leaf | Should -Be 'ArgosCCF'
        $root | Should -Not -BeLike "$moduleRoot*"
    }

    It 'writes logs and records outside the module folder' {
        $before = @(Get-ChildItem -LiteralPath $moduleRoot -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object FullName)
        Initialize-CCFLogger -FileName 'DataFolder.log'
        Write-CCFLogInfo 'into the data folder'
        Write-CCFAuditRecord -Action 'Test' -User 'bob'
        Join-Path $dataRoot 'Logs/DataFolder.log' | Should -Exist
        Join-Path $dataRoot 'Logs/CCF_Audit.log' | Should -Exist
        $after = @(Get-ChildItem -LiteralPath $moduleRoot -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object FullName)
        $after | Where-Object { $_ -notin $before } | Should -BeNullOrEmpty
    }
}

Describe 'Initialize-CCFLogger -Path' {
    AfterEach { InModuleScope ArgosCCF { $script:LogsPathOverride = $null } }

    It 'writes the session log and the category files to the chosen folder, creating it' {
        $folder = Join-Path $TestDrive 'script-logs'
        Initialize-CCFLogger -Path $folder -FileName 'Deploy.log'
        Write-CCFLogInfo 'deploying'
        Write-CCFSecurityRecord -Type 'Test' -Source 'Unit'
        Get-CCFPath -Target 'Logs' | Should -Be ([System.IO.Path]::GetFullPath($folder))
        Join-Path $folder 'Deploy.log' | Should -Exist
        Join-Path $folder 'CCF_Security.log' | Should -Exist
    }

    It 'resolves a relative path from the current location' {
        Push-Location $TestDrive
        try {
            Initialize-CCFLogger -Path 'relative-logs'
            Get-CCFPath -Target 'Logs' | Should -Be ([System.IO.Path]::GetFullPath((Join-Path $TestDrive 'relative-logs')))
        }
        finally { Pop-Location }
    }

    It 'throws when the folder cannot be written' {
        $file = Join-Path $TestDrive 'not-a-folder.txt'
        Set-Content -Path $file -Value 'x'
        { Initialize-CCFLogger -Path (Join-Path $file 'logs') } | Should -Throw '*cannot be created or written*'
    }
}

Describe 'User settings' {
    It 'Set-CCFUserConfig saves to the data folder and Get-CCFConfig reads it back' {
        $name = 'datafolder_' + [guid]::NewGuid().ToString('N').Substring(0, 6)
        Set-CCFUserConfig -ConfigName $name -ConfigObject ([pscustomobject]@{ Server = 'prod01' }) -Confirm:$false
        Join-Path (Get-CCFPath -Target 'UserConfigs') "$name.json" | Should -Exist
        Join-Path $moduleRoot "Configs/User/$name.json" | Should -Not -Exist
        (Get-CCFConfig -ConfigName $name -ForceRefresh).Server | Should -Be 'prod01'
    }

    It 'still reads settings saved next to the module by earlier versions, with the data folder winning' {
        $name = 'legacy_' + [guid]::NewGuid().ToString('N').Substring(0, 6)
        $legacyDir = Join-Path $moduleRoot 'Configs/User'
        $createdDir = -not (Test-Path $legacyDir)
        New-Item -ItemType Directory -Path $legacyDir -Force | Out-Null
        $legacy = Join-Path $legacyDir "$name.json"
        try {
            '{ "Server": "old01", "Port": 1433 }' | Set-Content -Path $legacy
            (Get-CCFConfig -ConfigName $name -ForceRefresh).Server | Should -Be 'old01'

            Set-CCFUserConfig -ConfigName $name -ConfigObject ([pscustomobject]@{ Server = 'new01' }) -Confirm:$false
            $config = Get-CCFConfig -ConfigName $name -ForceRefresh
            $config.Server | Should -Be 'new01'
            $config.Port | Should -Be 1433
        }
        finally {
            Remove-Item -LiteralPath $legacy -Force -ErrorAction SilentlyContinue
            if ($createdDir) { Remove-Item -LiteralPath $legacyDir -Force -ErrorAction SilentlyContinue }
        }
    }
}
