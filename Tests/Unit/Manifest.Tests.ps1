BeforeDiscovery {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    # PowerShell files with non-ASCII content must carry a UTF-8 BOM for Windows PowerShell 5.1.
    $script:nonAsciiFiles = Get-ChildItem -Path $repoRoot -Recurse -Include '*.ps1', '*.psm1', '*.psd1' |
        Where-Object { $_.FullName -notmatch '[\\/](\.git|output)[\\/]' } |
        Where-Object { [IO.File]::ReadAllBytes($_.FullName) | Where-Object { $_ -gt 127 } | Select-Object -First 1 } |
        ForEach-Object { @{ Path = $_.FullName; Name = $_.FullName.Substring($repoRoot.Length + 1) } }
}

BeforeAll {
    $manifestPath = Join-Path $PSScriptRoot '../../ArgosCCF.psd1'
    $manifest = Import-PowerShellDataFile -Path $manifestPath
    $module = Import-Module $manifestPath -Force -PassThru
}

Describe 'ArgosCCF manifest' {
    It 'targets Windows PowerShell 5.1 or later' {
        [version]$manifest.PowerShellVersion | Should -BeGreaterOrEqual ([version]'5.1')
    }

    It 'exports every function listed in the manifest, and nothing else' {
        $exported = @($module.ExportedFunctions.Keys)
        $manifest.FunctionsToExport | Where-Object { $_ -notin $exported } | Should -BeNullOrEmpty
        $exported | Where-Object { $_ -notin $manifest.FunctionsToExport } | Should -BeNullOrEmpty
    }

    It 'exports every alias listed in the manifest, and nothing else' {
        $exported = @($module.ExportedAliases.Keys)
        $manifest.AliasesToExport | Where-Object { $_ -notin $exported } | Should -BeNullOrEmpty
        $exported | Where-Object { $_ -notin $manifest.AliasesToExport } | Should -BeNullOrEmpty
    }

    It 'does not leave helper modules in the session' {
        Get-Module -Name Logging, Configuration, Plugins, Execution | Should -BeNullOrEmpty
    }

    It 'reports a healthy installation' {
        (Test-CCFHealth).Status | Should -Be 'OK'
    }
}

Describe 'Source file encoding' {
    It '<Name> has a UTF-8 BOM' -ForEach $nonAsciiFiles {
        $bytes = [IO.File]::ReadAllBytes($Path)
        ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) | Should -BeTrue
    }
}
