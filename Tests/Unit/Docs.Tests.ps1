BeforeDiscovery {
    $manifest = Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot '../../ArgosCCF.psd1')
    $script:names = @($manifest.FunctionsToExport + $manifest.AliasesToExport | ForEach-Object { @{ Name = $_ } })
}

Describe 'Docs/API-Reference.md' {
    BeforeAll {
        $reference = Get-Content -Path (Join-Path $PSScriptRoot '../../Docs/API-Reference.md') -Raw -Encoding UTF8
    }

    It 'documents <Name> (regenerate with Docs/New-ApiReference.ps1)' -ForEach $names {
        $reference | Should -Match ([regex]::Escape("``$Name``"))
    }
}
